package server

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/zjyl1994/arkauthn/infra/utils"
	"github.com/zjyl1994/arkauthn/infra/vars"
	"golang.org/x/crypto/bcrypt"
)

func forwardAuthHandler(c *fiber.Ctx) error {
	forwardMethod := c.Get("X-Forwarded-Method")
	forwardUri := fmt.Sprintf("%s://%s%s", c.Get("X-Forwarded-Proto"), c.Get("X-Forwarded-Host"), c.Get("X-Forwarded-Uri"))
	logrus.Debugf("ForwardAuth with %s %s", forwardMethod, forwardUri)
	userinfo, ok := c.Locals(authUserKey).(authUserType)
	if !ok {
		if strings.EqualFold(forwardMethod, "GET") {
			u, err := url.Parse(vars.Config.Redirect)
			if err != nil {
				return c.Status(http.StatusInternalServerError).SendString(err.Error())
			}
			query := u.Query()
			query.Set("r", forwardUri)
			u.RawQuery = query.Encode()
			return c.Redirect(u.String(), fiber.StatusSeeOther)
		} else {
			return c.SendStatus(http.StatusUnauthorized)
		}
	}
	c.Set("Remote-User", userinfo.Username)
	c.Set("X-Forwarded-User", userinfo.Username)
	logrus.Debugf("ForwardAuth success with user:%s", userinfo.Username)
	return c.SendStatus(http.StatusNoContent)
}

func loginAuthnHandler(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username" form:"username"`
		Password string `json:"password" form:"password"`
		Redirect string `json:"redirect" form:"redirect"`
		CapToken string `json:"cap_token" form:"cap_token"`
		Duration int64  `json:"duration" form:"duration"`
	}
	err := c.BodyParser(&req)
	if err != nil {
		return err
	}
	if req.CapToken == "" || !vars.CapInstance.ValidateToken(req.CapToken, false) {
		return c.SendStatus(fiber.StatusUnauthorized)
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
	var dur = time.Duration(vars.Config.TokenExpire) * time.Second
	if req.Duration >= 3600 && req.Duration <= 31536000 {
		dur = time.Duration(req.Duration) * time.Second
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
		Name:        "arkauthn",
		Value:       token,
		Expires:     expireAt,
		HTTPOnly:    true,
		Domain:      "." + rootDomain,
		SessionOnly: true,
	}
	c.Cookie(cookie)
	// 重定向
	if len(req.Redirect) > 0 {
		return c.Redirect(req.Redirect, fiber.StatusSeeOther)
	}
	return c.Render("index", fiber.Map{
		"username": user,
		"expire":   expireAt.Unix(),
	})
}

func indexHandler(c *fiber.Ctx) error {
	userinfo, ok := c.Locals(authUserKey).(authUserType)
	if !ok { // 没有登录
		return c.Render("login", fiber.Map{})
	}
	return c.Render("index", fiber.Map{
		"username": userinfo.Username,
		"expire":   userinfo.Expire.Unix(),
	})
}

func logoutHandler(c *fiber.Ctx) error {
	c.ClearCookie("arkauthn")
	return c.Render("logout", fiber.Map{})
}

func checkUser(username, password string) (string, bool) {
	for _, u := range vars.Config.Users {
		if u.Username == username {
			if strings.HasPrefix(u.Password, "$2a$") || strings.HasPrefix(u.Password, "$2b$") || strings.HasPrefix(u.Password, "$2y$") {
				if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) == nil {
					return u.Username, true
				}
			} else if subtle.ConstantTimeCompare([]byte(password), []byte(u.Password)) > 0 {
				return u.Username, true
			}
		}
	}
	return "", false
}
