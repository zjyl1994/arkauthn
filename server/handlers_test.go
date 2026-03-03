package server

import (
	"encoding/base64"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/zjyl1994/arkauthn/infra/vars"
)

func TestForwardAuthHandlerRedirect(t *testing.T) {
	oldRedirect := vars.Config.Redirect
	vars.Config.Redirect = "http://auth.example.com/login"
	t.Cleanup(func() {
		vars.Config.Redirect = oldRedirect
	})
	app := fiber.New()
	app.Get("/api/forward-auth", forwardAuthHandler)

	req := httptest.NewRequest("GET", "/api/forward-auth", nil)
	req.Header.Set("X-Forwarded-Method", "GET")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "example.com")
	req.Header.Set("X-Forwarded-Uri", "/path")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != fiber.StatusSeeOther {
		t.Fatalf("expected see other")
	}
	location := resp.Header.Get("Location")
	u, err := url.Parse(vars.Config.Redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	q := u.Query()
	q.Set("r", "http://example.com/path")
	u.RawQuery = q.Encode()
	if location != u.String() {
		t.Fatalf("unexpected redirect: %s", location)
	}
}

func TestForwardAuthHandlerUnauthorized(t *testing.T) {
	app := fiber.New()
	app.Post("/api/forward-auth", forwardAuthHandler)

	req := httptest.NewRequest("POST", "/api/forward-auth", nil)
	req.Header.Set("X-Forwarded-Method", "POST")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("expected unauthorized")
	}
}

func TestForwardAuthHandlerSuccess(t *testing.T) {
	app := fiber.New()
	app.Get("/api/forward-auth", func(c fiber.Ctx) error {
		c.Locals(authUserKey, authUserType{Username: "alice", Expire: time.Now().Add(time.Hour)})
		return forwardAuthHandler(c)
	})

	req := httptest.NewRequest("GET", "/api/forward-auth", nil)
	req.Header.Set("X-Forwarded-Method", "GET")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	req.Header.Set("X-Forwarded-Uri", "/path")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("expected no content")
	}
	if resp.Header.Get("Remote-User") != "alice" {
		t.Fatalf("missing remote user")
	}
	if resp.Header.Get("X-Forwarded-User") != "alice" {
		t.Fatalf("missing forwarded user")
	}
}

func TestPublicConfigHandler(t *testing.T) {
	oldRole := vars.NodeRole
	oldRedirect := vars.Config.Redirect
	oldPub := vars.Ed25519PublicKey
	vars.NodeRole = vars.NodeRoleMaster
	vars.Config.Redirect = "http://auth.example.com"
	vars.Ed25519PublicKey = []byte("pubkey")
	t.Cleanup(func() {
		vars.NodeRole = oldRole
		vars.Config.Redirect = oldRedirect
		vars.Ed25519PublicKey = oldPub
	})
	app := fiber.New()
	app.Get("/.well-known/arkauthn.json", publicConfigHandler)

	req := httptest.NewRequest("GET", "/.well-known/arkauthn.json", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected ok")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	expectedKey := base64.StdEncoding.EncodeToString([]byte("pubkey"))
	if !containsAll(string(body), []string{vars.Config.Redirect, expectedKey}) {
		t.Fatalf("unexpected body: %s", string(body))
	}
}

func TestPublicConfigHandlerReplica(t *testing.T) {
	oldRole := vars.NodeRole
	vars.NodeRole = vars.NodeRoleReplica
	t.Cleanup(func() {
		vars.NodeRole = oldRole
	})
	app := fiber.New()
	app.Get("/.well-known/arkauthn.json", publicConfigHandler)

	req := httptest.NewRequest("GET", "/.well-known/arkauthn.json", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("expected not found")
	}
}

func TestRedirectToMaster(t *testing.T) {
	oldRedirect := vars.Config.Redirect
	vars.Config.Redirect = "http://auth.example.com/login"
	t.Cleanup(func() {
		vars.Config.Redirect = oldRedirect
	})
	app := fiber.New()
	app.Get("/redirect", func(c fiber.Ctx) error {
		return redirectToMaster(c, "http://target.example.com/path")
	})

	req := httptest.NewRequest("GET", "/redirect", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != fiber.StatusSeeOther {
		t.Fatalf("expected see other")
	}
	location := resp.Header.Get("Location")
	u, err := url.Parse(vars.Config.Redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	q := u.Query()
	q.Set("r", "http://target.example.com/path")
	u.RawQuery = q.Encode()
	if location != u.String() {
		t.Fatalf("unexpected redirect: %s", location)
	}
}

func containsAll(text string, parts []string) bool {
	for _, part := range parts {
		if !strings.Contains(text, part) {
			return false
		}
	}
	return true
}
