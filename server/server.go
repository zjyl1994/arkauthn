package server

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/gofiber/template/html/v3"
	"github.com/zjyl1994/arkauthn/infra/utils"
	"github.com/zjyl1994/arkauthn/infra/vars"
	"github.com/zjyl1994/arkauthn/web"
)

const cspNonceKey = "__CSP_NONCE__"

func Run(shutdownContext context.Context) error {
	mime.AddExtensionType(".wasm", "application/wasm")

	embedAssets, err := web.GetHttpAssets()
	if err != nil {
		return err
	}

	engine := html.NewFileSystem(http.FS(embedAssets), ".html")
	app := fiber.New(fiber.Config{
		Views:             engine,
		ViewsLayout:       "layout",
		PassLocalsToViews: true,
		TrustProxy:        len(vars.Config.TrustedProxies) > 0,
		TrustProxyConfig: fiber.TrustProxyConfig{
			Proxies: vars.Config.TrustedProxies,
		},
		ProxyHeader:  fiber.HeaderXForwardedFor,
		ServerHeader: "",
		AppName:      vars.APP_NAME,
	})

	app.Use(recover.New())

	// Add Security Headers
	app.Use(func(c fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "SAMEORIGIN")
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if c.Protocol() == "https" || strings.HasPrefix(vars.Config.Redirect, "https") {
			c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		cspNonce := utils.RandString(32)
		c.Locals(cspNonceKey, cspNonce)
		c.Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s' 'wasm-unsafe-eval'; style-src 'self' 'nonce-%s'; font-src 'self'; img-src 'self' data:; worker-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';", cspNonce, cspNonce))
		return c.Next()
	})

	app.Use(authTokenMiddleware)
	app.Get("/.well-known/arkauthn.json", publicConfigHandler)
	app.Get("/", indexHandler)
	app.Post("/", loginAuthnHandler)
	app.Get("/token", tokenPageHandler)
	app.Post("/api/token", tokenGenerateHandler)
	app.Post("/logout", logoutHandler)
	app.Get("/api/forward-auth", forwardAuthHandler)

	// Rate limiter for CAPTCHA endpoints
	capLimiter := limiter.New(limiter.Config{
		Max:        20, // 20 requests per minute
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).SendString("Too many requests")
		},
	})

	app.Post("/api/cap/challenge", capLimiter, createChallengeHandler)
	app.Post("/api/cap/redeem", capLimiter, redeemChallengeHandler)

	app.Use(static.New("", static.Config{
		FS:     embedAssets,
		MaxAge: int((7 * 24 * time.Hour).Seconds()),
	}))
	if shutdownContext == nil {
		shutdownContext = context.Background()
	}
	return app.Listen(vars.Config.Listen, fiber.ListenConfig{
		DisableStartupMessage: true,
		GracefulContext:       shutdownContext,
	})
}
