package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/samber/lo"
	"github.com/zjyl1994/arkauthn/infra/utils"
)

type authUserNameType struct{}

var authUserNameKey authUserNameType

func authTokenMiddleware(c *fiber.Ctx) error {
	token, ok := lo.Coalesce(c.Query("arkauthn"), c.Cookies("arkauthn"), c.Get("X-Arkauthn"))
	if ok {
		username, err := utils.ParseToken(token)
		if err == nil {
			c.Locals(authUserNameKey, username)
		}
	}
	return c.Next()
}
