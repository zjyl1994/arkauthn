package server

import (
	"github.com/gofiber/fiber/v2"
)

func forwardAuthHandler(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusNoContent)
}

func loginPageHandler(c *fiber.Ctx) error {
	return c.Render("login", fiber.Map{})
}

func loginAuthnHandler(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	err := c.BodyParser(&req)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"user": req.Username,
		"pass": req.Password,
	})
}
