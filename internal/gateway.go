package internal

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"github.com/laudryfadian/griyo-backend-service-gateway/internal/domain"
	"github.com/laudryfadian/griyo-backend-service-gateway/internal/pb"
	"github.com/laudryfadian/griyo-backend-service-gateway/internal/platform"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed docs/*
var docs embed.FS

type Service struct {
	workspace pb.WorkspaceServiceClient
	fleet     pb.FleetServiceClient
	tasks     pb.TaskServiceClient
	password  string
	secret    string
	secure    bool
}

func New(w pb.WorkspaceServiceClient, f pb.FleetServiceClient, t pb.TaskServiceClient) *Service {
	return &Service{workspace: w, fleet: f, tasks: t, password: platform.Require("OWNER_PASSWORD"), secret: platform.Require("SESSION_SECRET"), secure: platform.Env("COOKIE_SECURE", "false") == "true"}
}
func (s *Service) signature(value string) string {
	h := hmac.New(sha256.New, []byte(s.secret))
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Service) authenticated(r *http.Request) bool {
	c, e := r.Cookie("griyoSession")
	if e != nil {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 || !platform.Equal(s.signature(parts[0]), parts[1]) {
		return false
	}
	expiry, e := strconv.ParseInt(parts[0], 10, 64)
	return e == nil && time.Now().Unix() < expiry
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/healthz" {
		w.Write([]byte("ok"))
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		origin := r.Header.Get("Origin")
		if origin != "" && origin != platform.Env("APP_ORIGIN", "http://localhost:3000") {
			platform.HttpError(w, status.Error(codes.PermissionDenied, "origin not allowed"))
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	body := []byte{}
	if r.Body != nil {
		var e error
		body, e = io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if e != nil {
			platform.HttpError(w, platform.Invalid("request too large"))
			return
		}
	}
	if r.URL.Path == "/api/auth/login" && r.Method == "POST" {
		var input struct {
			Password string `json:"password"`
		}
		if e := platform.Decode(body, &input); e != nil {
			platform.HttpError(w, e)
			return
		}
		if !platform.Equal(platform.Hash(input.Password), platform.Hash(s.password)) {
			time.Sleep(500 * time.Millisecond)
			platform.HttpError(w, status.Error(codes.Unauthenticated, "invalid password"))
			return
		}
		expiry := strconv.FormatInt(time.Now().Add(12*time.Hour).Unix(), 10)
		http.SetCookie(w, &http.Cookie{Name: "griyoSession", Value: expiry + "." + s.signature(expiry), Path: "/", HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authenticated":true}`))
		return
	}
	if r.URL.Path == "/api/auth/logout" && r.Method == "POST" {
		http.SetCookie(w, &http.Cookie{Name: "griyoSession", Value: "", Path: "/", HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		w.WriteHeader(204)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/runner/") {
		s.runner(ctx, w, r, body)
		return
	}
	if !s.authenticated(r) {
		platform.HttpError(w, status.Error(codes.Unauthenticated, "login required"))
		return
	}
	if r.URL.Path == "/api/auth/session" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authenticated":true}`))
		return
	}
	if r.URL.Path == "/api/openapi.json" {
		b, e := docs.ReadFile("docs/openapi.json")
		if e != nil {
			platform.HttpError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
		return
	}
	if r.URL.Path == "/api/docs" {
		b, _ := docs.ReadFile("docs/index.html")
		w.Header().Set("Content-Type", "text/html")
		w.Write(b)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "api" {
		http.NotFound(w, r)
		return
	}
	resource := parts[1]
	id := ""
	if len(parts) > 2 {
		id = parts[2]
	}
	operation := ""
	switch r.Method {
	case "GET":
		operation = "list"
		if id != "" {
			operation = "get"
		}
	case "POST":
		operation = "create"
	case "PUT", "PATCH":
		operation = "update"
	default:
		w.WriteHeader(405)
		return
	}
	if len(parts) > 3 {
		switch parts[3] {
		case "pair", "revoke":
			if resource != "servers" || r.Method != "POST" {
				http.NotFound(w, r)
				return
			}
			operation = parts[3]
		case "commands":
			if resource != "servers" {
				http.NotFound(w, r)
				return
			}
			resource = "commands"
			if r.Method == "POST" {
				var c domain.ContainerCommand
				if e := platform.Decode(body, &c); e != nil {
					platform.HttpError(w, e)
					return
				}
				c.ServerId = id
				body, _ = json.Marshal(c)
			}
		case "messages":
			if resource != "tasks" {
				http.NotFound(w, r)
				return
			}
			resource = "messages"
		case "approval":
			if resource != "tasks" || r.Method != "POST" {
				http.NotFound(w, r)
				return
			}
			resource = "approvals"
			operation = "create"
		default:
			http.NotFound(w, r)
			return
		}
	}
	if len(parts) > 4 || (r.Method == "POST" && len(parts) == 3) || ((r.Method == "PUT" || r.Method == "PATCH") && id == "" && resource != "settings") {
		http.NotFound(w, r)
		return
	}
	if resource == "settings" && r.Method == "GET" {
		operation = "get"
		id = "workspace"
	}
	req := platform.Request(operation, resource, id, body)
	var res *pb.Response
	var e error
	switch resource {
	case "agents", "projects", "documents", "settings":
		res, e = s.workspace.Execute(ctx, req)
	case "servers", "commands":
		res, e = s.fleet.Execute(ctx, req)
	case "tasks", "messages", "approvals", "events":
		res, e = s.tasks.Execute(ctx, req)
	default:
		http.NotFound(w, r)
		return
	}
	if e != nil {
		platform.HttpError(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if operation == "create" {
		w.WriteHeader(201)
	}
	w.Write(res.Body)
}
func (s *Service) runner(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		platform.HttpError(w, status.Error(codes.Unauthenticated, "runner token required"))
		return
	}
	b, _ := json.Marshal(domain.TokenHash{TokenHash: platform.Hash(token)})
	res, e := s.fleet.Execute(ctx, platform.Request("authenticate", "servers", "", b))
	if e != nil {
		platform.HttpError(w, e)
		return
	}
	var identity domain.RunnerIdentity
	if e = json.Unmarshal(res.Body, &identity); e != nil {
		platform.HttpError(w, e)
		return
	}
	serverId := identity.ServerId
	switch {
	case r.URL.Path == "/api/runner/heartbeat" && r.Method == "POST":
		res, e = s.fleet.Execute(ctx, platform.Request("heartbeat", "servers", serverId, body))
	case r.URL.Path == "/api/runner/claim" && r.Method == "POST":
		res, e = s.tasks.Execute(ctx, platform.Request("claim", "tasks", serverId, nil))
	case strings.HasPrefix(r.URL.Path, "/api/runner/tasks/") && r.Method == "POST":
		id := strings.TrimPrefix(r.URL.Path, "/api/runner/tasks/")
		var taskRes *pb.Response
		taskRes, e = s.tasks.Execute(ctx, platform.Request("get", "tasks", id, nil))
		if e == nil {
			var t domain.Task
			e = json.Unmarshal(taskRes.Body, &t)
			if e == nil && t.WorkServerId != serverId {
				e = status.Error(codes.PermissionDenied, "task belongs to another server")
			}
			if e == nil {
				res, e = s.tasks.Execute(ctx, platform.Request("report", "tasks", id, body))
			}
		}
	case r.URL.Path == "/api/runner/commands/claim" && r.Method == "POST":
		res, e = s.fleet.Execute(ctx, platform.Request("claim", "commands", serverId, nil))
	case r.URL.Path == "/api/runner/commands/report" && r.Method == "POST":
		res, e = s.fleet.Execute(ctx, platform.Request("report", "commands", serverId, body))
	default:
		http.NotFound(w, r)
		return
	}
	if e != nil {
		platform.HttpError(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(res.Body)
}
