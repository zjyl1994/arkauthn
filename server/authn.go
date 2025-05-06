package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/zjyl1994/arkauthn/infra/utils"
	"github.com/zjyl1994/arkauthn/infra/vars"
)

func forwardAuthHandler(c *fiber.Ctx) error {
	forwardMethod := c.Get("X-Forwarded-Method")
	forwardUri := fmt.Sprintf("%s://%s%s", c.Get("X-Forwarded-Proto"), c.Get("X-Forwarded-Host"), c.Get("X-Forwarded-Uri"))
	logrus.Debugf("ForwardAuth with %s %s", forwardMethod, forwardUri)
	username, ok := c.Locals(authUserNameKey).(string)
	if !ok {
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
	ipAddr := c.IP()
	if vars.AuthRateLimiter != nil && vars.AuthRateLimiter.IsLimited(ipAddr) {
		logrus.Warnf("Too many login attempts %s", ipAddr)
		return c.Status(http.StatusTooManyRequests).SendString("Too many login attempts")
	}
	logrus.Debugf("Access Remote IP %s", ipAddr)
	user, ok := checkUser(req.Username, req.Password)
	if !ok { // 用户名密码错误
		if vars.AuthRateLimiter != nil {
			vars.AuthRateLimiter.RecordError(ipAddr)
		}
		logrus.Warnf("Invalid login attempt %s", ipAddr) // 记录警告日志方便后续fail2ban
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
	return c.Render("index", fiber.Map{
		"username": user,
		"token":    token,
		"expire":   expireAt.Format(time.DateTime),
	})
}

func indexHandler(c *fiber.Ctx) error {
	username, ok := c.Locals(authUserNameKey).(string)
	if !ok { // 没有登录
		return c.Render("login", fiber.Map{})
	}
	return c.Render("index", fiber.Map{"username": username})
}

func logoutHandler(c *fiber.Ctx) error {
	c.ClearCookie("arkauthn")
	return c.Render("logout", fiber.Map{})
}

func checkUser(username, password string) (string, bool) {
	for _, u := range vars.Config.Users {
		if u.Username == username && u.Password == password {
			return u.Username, true
		}
	}
	return "", false
}
