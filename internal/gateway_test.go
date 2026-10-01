package internal

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testService() *Service {
	return &Service{password: strings.Repeat("p", 32), secret: strings.Repeat("s", 32)}
}
func TestSessionCookieValidation(t *testing.T) {
	s := testService()
	expiry := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	for _, test := range []struct {
		value string
		valid bool
	}{{expiry + "." + s.signature(expiry), true}, {expiry + ".tampered", false}, {"1." + s.signature("1"), false}} {
		r := httptest.NewRequest("GET", "/api/auth/session", nil)
		r.AddCookie(&http.Cookie{Name: "griyoSession", Value: test.value})
		if s.authenticated(r) != test.valid {
			t.Fatalf("cookie validation mismatch")
		}
	}
}
func TestApiNeedsLogin(t *testing.T) {
	s := testService()
	response := httptest.NewRecorder()
	s.ServeHTTP(response, httptest.NewRequest("GET", "/api/projects", nil))
	if response.Code != 401 {
		t.Fatalf("expected 401, got %d", response.Code)
	}
}
func TestLoginAndOrigin(t *testing.T) {
	s := testService()
	t.Setenv("APP_ORIGIN", "http://localhost:3000")
	for _, origin := range []string{"http://localhost:3000", "https://evil.test"} {
		r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"password":"`+s.password+`"}`))
		r.Header.Set("Origin", origin)
		response := httptest.NewRecorder()
		s.ServeHTTP(response, r)
		if origin == "https://evil.test" {
			if response.Code != 403 {
				t.Fatal("cross-origin login accepted")
			}
		} else {
			cookies := response.Result().Cookies()
			if response.Code != 200 || len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
				t.Fatal("invalid login cookie")
			}
		}
	}
}
