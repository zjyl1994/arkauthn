package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/zjyl1994/arkauthn/infra/utils"
	"github.com/zjyl1994/arkauthn/infra/vars"
)

func setServerTestKeys(t *testing.T) {
	t.Helper()
	oldPub := vars.Ed25519PublicKey
	oldPriv := vars.Ed25519PrivateKey
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	vars.Ed25519PublicKey = pub
	vars.Ed25519PrivateKey = priv
	t.Cleanup(func() {
		vars.Ed25519PublicKey = oldPub
		vars.Ed25519PrivateKey = oldPriv
	})
}

func TestAuthTokenMiddlewareFromHeader(t *testing.T) {
	setServerTestKeys(t)
	token, err := utils.GenerateToken("alice", time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	app := fiber.New()
	app.Use(authTokenMiddleware)
	app.Get("/", func(c fiber.Ctx) error {
		user, ok := c.Locals(authUserKey).(authUserType)
		if !ok {
			return c.SendString("")
		}
		return c.SendString(user.Username)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Arkauthn", token)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "alice" {
		t.Fatalf("expected username")
	}
}

func TestAuthTokenMiddlewareFromCookie(t *testing.T) {
	setServerTestKeys(t)
	token, err := utils.GenerateToken("bob", time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	app := fiber.New()
	app.Use(authTokenMiddleware)
	app.Get("/", func(c fiber.Ctx) error {
		user, ok := c.Locals(authUserKey).(authUserType)
		if !ok {
			return c.SendString("")
		}
		return c.SendString(user.Username)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "arkauthn", Value: token})
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "bob" {
		t.Fatalf("expected username")
	}
}

func TestAuthTokenMiddlewareInvalidToken(t *testing.T) {
	app := fiber.New()
	app.Use(authTokenMiddleware)
	app.Get("/", func(c fiber.Ctx) error {
		_, ok := c.Locals(authUserKey).(authUserType)
		if ok {
			return c.SendString("set")
		}
		return c.SendString("")
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Arkauthn", "invalid")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "" {
		t.Fatalf("expected empty body")
	}
}
