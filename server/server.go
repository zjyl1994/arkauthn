package server

import (
	"fmt"
	"mime"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/template/html/v2"
	"github.com/zjyl1994/arkauthn/infra/utils"
	"github.com/zjyl1994/arkauthn/web"
)

const cspNonceKey = "__CSP_NONCE__"

func Run(listen string) error {
	mime.AddExtensionType(".wasm", "application/wasm")

	embedAssets, err := web.GetHttpAssets()
	if err != nil {
		return err
	}

	engine := html.NewFileSystem(embedAssets, ".html")
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		Views:                 engine,
		ViewsLayout:           "layout",
		PassLocalsToViews:     true,
	})

	// Add Security Headers
	app.Use(func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "SAMEORIGIN")
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if c.Protocol() == "https" {
			c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		cspNonce := utils.RandString(32)
		c.Locals(cspNonceKey, cspNonce)
		c.Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s' 'wasm-unsafe-eval'; style-src 'self' 'nonce-%s'; font-src 'self'; img-src 'self' data:; worker-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';", cspNonce, cspNonce))
		return c.Next()
	})

	app.Use(authTokenMiddleware)
	app.Get("/", indexHandler)
	app.Post("/", loginAuthnHandler)
	app.Get("/logout", logoutHandler)
	app.Get("/api/forward-auth", forwardAuthHandler)

	// Rate limiter for CAPTCHA endpoints
	capLimiter := limiter.New(limiter.Config{
		Max:        20, // 20 requests per minute
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).SendString("Too many requests")
		},
	})

	app.Post("/api/cap/challenge", capLimiter, createChallengeHandler)
	app.Post("/api/cap/redeem", capLimiter, redeemChallengeHandler)

	app.Use(filesystem.New(filesystem.Config{
		Root:   embedAssets,
		MaxAge: int((7 * 24 * time.Hour).Seconds()),
	}))
	return app.Listen(listen)
}
