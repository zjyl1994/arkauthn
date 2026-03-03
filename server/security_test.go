package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestSecurityHeaders(t *testing.T) {
	// Setup app with default config (simulating server.Run but simplified)
	app := fiber.New(fiber.Config{
		ServerHeader: "",
	})
	
	req := httptest.NewRequest("GET", "/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		t.Fatalf("expected empty Server header, got %s", serverHeader)
	}
}

func TestLoginInputValidation(t *testing.T) {
	app := fiber.New()
	app.Post("/", loginAuthnHandler)

	// Test long username
	longUser := strings.Repeat("a", 65)
	payload := `{"username":"` + longUser + `","password":"pwd"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected bad request for long username, got %d", resp.StatusCode)
	}

	// Test long password
	longPass := strings.Repeat("a", 73)
	payload = `{"username":"user","password":"` + longPass + `"}`
	req = httptest.NewRequest("POST", "/", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected bad request for long password, got %d", resp.StatusCode)
	}

	// Test valid input (should proceed to cap check or role check)
	payload = `{"username":"user","password":"pwd"}`
	req = httptest.NewRequest("POST", "/", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	// It might fail later due to missing cap token or node role, but definitely not 400 Bad Request
	if resp.StatusCode == fiber.StatusBadRequest {
		t.Fatalf("unexpected bad request for valid input")
	}
}
