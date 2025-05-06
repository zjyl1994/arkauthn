package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/zjyl1994/arkauthn/infra/utils"
	"github.com/zjyl1994/arkauthn/infra/vars"
)

func forwardAuthHandler(c *fiber.Ctx) error {
	forwardMethod := c.Get("X-Forwarded-Method")
	forwardUri := fmt.Sprintf("%s://%s%s", c.Get("X-Forwarded-Proto"), c.Get("X-Forwarded-Host"), c.Get("X-Forwarded-Uri"))
	logrus.Debugf("ForwardAuth with %s %s", forwardMethod, forwardUri)
	unauthorized := func() error {
		if strings.EqualFold(forwardMethod, "GET") {
			u, err := url.Parse(vars.Config.Redirect)
			if err != nil {
				return c.Status(http.StatusInternalServerError).SendString(err.Error())
			}
			query := u.Query()
			query.Set("r", forwardUri)
			u.RawQuery = query.Encode()
			return c.Redirect(u.String())
		} else {
			return c.SendStatus(http.StatusUnauthorized)
		}
	}
	token, ok := lo.Coalesce(c.Query("arkauthn"), c.Cookies("arkauthn"), c.Get("X-Arkauthn"))
	if !ok {
		return unauthorized()
	}

	username, err := utils.ParseToken(token)
	if err != nil || username == "" {
		return unauthorized()
	}
	c.Set("Remote-User", username)
	logrus.Debugf("ForwardAuth success with user:%s", username)
	return c.SendStatus(http.StatusNoContent)
}

func loginAuthnHandler(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username" form:"username"`
		Password string `json:"password" form:"password"`
		Remember string `json:"remember" form:"remember"`
		Redirect string `json:"redirect" form:"redirect"`
	}
	err := c.BodyParser(&req)
	if err != nil {
		return err
	}
	user, ok := checkUser(req.Username, req.Password)
	if !ok { // 用户名密码错误
		u, uerr := url.Parse(vars.Config.Redirect)
		if uerr != nil {
			return uerr
		}
		q := u.Query()
		q.Set("e", "1")
		if len(req.Redirect) > 0 {
			q.Set("r", req.Redirect)
		}
		u.RawQuery = q.Encode()
		return c.Redirect(u.String())
	}
	// 生成JWT令牌
	var dur time.Duration
	if len(req.Remember) > 0 {
		dur = 30 * 24 * time.Hour
	} else {
		dur = time.Hour
	}
	token, err := utils.GenerateToken(user, dur)
	if err != nil {
		return err
	}
	// 设置cookie
	rootDomain, err := utils.ExtractRootDomain(vars.Config.Redirect)
	if err != nil {
		return err
	}
	expireAt := time.Now().Add(dur)
	cookie := &fiber.Cookie{
		Name:     "arkauthn",
		Value:    token,
		Expires:  expireAt,
		HTTPOnly: true,
		Domain:   "." + rootDomain,
	}
	if len(req.Remember) == 0 {
		cookie.SessionOnly = true
	}
	c.Cookie(cookie)
	// 重定向
	if len(req.Redirect) > 0 {
		return c.Redirect(req.Redirect)
	}
	return c.SendString(fmt.Sprintf("登录成功，欢迎 %s\n您的token: %s\n过期时间: %s", user, token, expireAt.Format(time.DateTime)))
}

func checkUser(username, password string) (string, bool) {
	for _, u := range vars.Config.Users {
		if u.Username == username && u.Password == password {
			return u.Username, true
		}
	}
	return "", false
}
