package server

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/zjyl1994/arkauthn/web"
)

var publicFileHandler = filesystem.New(filesystem.Config{
	Root:       http.FS(web.PublicFiles),
	PathPrefix: "public",
	Index:      "index.html",
})

func Run(listen string) error {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	app.Post("/", loginAuthnHandler)
	app.Get("/logout", logoutHandler)

	app.Use(authTokenMiddleware)
	app.Get("/api/forward-auth", forwardAuthHandler)
	app.Get("/", indexHandler)

	app.Use(publicFileHandler)
	return app.Listen(listen)
}
