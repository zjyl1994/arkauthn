package server

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/template/html/v2"
	"github.com/zjyl1994/arkauthn/web"
)

func Run(listen string) error {
	engine := html.New("./web/template", ".html")
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		Views:                 engine,
	})
	publicFS := http.FS(web.PublicFiles)
	app.Use(favicon.New(favicon.Config{File: "public/favicon.ico", FileSystem: publicFS}))

	app.Get("/api/forward-auth", forwardAuthHandler)
	app.Get("/", loginPageHandler)
	app.Post("/", loginAuthnHandler)
	return app.Listen(listen)
}
