package server

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/zjyl1994/arkauthn/web"
)

func Run(listen string) error {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	app.Get("/api/forward-auth", forwardAuthHandler)
	app.Post("/", loginAuthnHandler)

	app.Use(filesystem.New(filesystem.Config{
		Root:       http.FS(web.PublicFiles),
		PathPrefix: "public",
		Index:      "index.html",
	}))
	return app.Listen(listen)
}
