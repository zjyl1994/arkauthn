package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/template/html/v2"
	"github.com/zjyl1994/arkauthn/web"
)

func Run(listen string) error {
	embedAssets, err := web.GetHttpAssets()
	if err != nil {
		return err
	}

	engine := html.NewFileSystem(embedAssets, ".html")
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		Views:                 engine,
		ViewsLayout:           "layout",
	})

	app.Use(authTokenMiddleware)
	app.Get("/", indexHandler)
	app.Post("/", loginAuthnHandler)
	app.Get("/logout", logoutHandler)
	app.Get("/api/forward-auth", forwardAuthHandler)

	app.Use(filesystem.New(filesystem.Config{Root: embedAssets}))
	return app.Listen(listen)
}
