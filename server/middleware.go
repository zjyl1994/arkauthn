package server

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/samber/lo"
	"github.com/zjyl1994/arkauthn/infra/utils"
)

type authUserType struct {
	Username string
	Expire   time.Time
}

var authUserKey authUserType

func authTokenMiddleware(c *fiber.Ctx) error {
	token, ok := lo.Coalesce(c.Cookies("arkauthn"), c.Get("X-Arkauthn"))
	if ok {
		username, expire, err := utils.ParseToken(token)
		if err == nil {
			c.Locals(authUserKey, authUserType{
				Username: username,
				Expire:   expire,
			})
		}
	}
	return c.Next()
}
