package main

import (
	app "github.com/laudryfadian/griyo-backend-service-gateway/internal"
	"github.com/laudryfadian/griyo-backend-service-gateway/internal/pb"
	"github.com/laudryfadian/griyo-backend-service-gateway/internal/platform"
	"log"
	"net/http"
	"time"
)

func main() {
	w, e := platform.Dial(platform.Env("WORKSPACE_GRPC_ADDR", "workspace:50051"))
	if e != nil {
		log.Fatal(e)
	}
	defer w.Close()
	f, e := platform.Dial(platform.Env("FLEET_GRPC_ADDR", "fleet:50052"))
	if e != nil {
		log.Fatal(e)
	}
	defer f.Close()
	t, e := platform.Dial(platform.Env("TASK_GRPC_ADDR", "task:50053"))
	if e != nil {
		log.Fatal(e)
	}
	defer t.Close()
	server := &http.Server{Addr: platform.Env("HTTP_ADDR", ":8080"), Handler: app.New(pb.NewWorkspaceServiceClient(w), pb.NewFleetServiceClient(f), pb.NewTaskServiceClient(t)), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	log.Fatal(server.ListenAndServe())
}
