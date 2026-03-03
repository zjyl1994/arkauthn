package server

import (
	"github.com/gofiber/fiber/v3"
	"github.com/zjyl1994/arkauthn/infra/vars"
	"github.com/zjyl1994/cap-go"
)

func createChallengeHandler(c fiber.Ctx) error {
	challenge := vars.CapInstance.CreateChallenge(nil)
	return c.JSON(challenge)
}

func redeemChallengeHandler(c fiber.Ctx) error {
	var body cap.Solution
	err := c.Bind().Body(&body)
	if err != nil {
		return err
	}
	resp := vars.CapInstance.RedeemChallenge(&body)
	return c.JSON(resp)
}
