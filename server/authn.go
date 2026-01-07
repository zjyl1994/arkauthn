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

var dummyBcryptHash []byte

func init() {
	dummyBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("dummy_password_for_timing_protection"), bcrypt.DefaultCost)
}

func forwardAuthHandler(c *fiber.Ctx) error {
	forwardMethod := c.Get("X-Forwarded-Method")
	forwardUri := fmt.Sprintf("%s://%s%s", c.Get("X-Forwarded-Proto"), c.Get("X-Forwarded-Host"), c.Get("X-Forwarded-Uri"))
	logrus.Debugf("ForwardAuth with %s %s", forwardMethod, forwardUri)
	userinfo, ok := c.Locals(authUserKey).(authUserType)
	if !ok {
		if strings.EqualFold(forwardMethod, "GET") {
			u, err := url.Parse(vars.Config.Redirect)
			if err != nil {
				logrus.Errorf("Invalid redirect config: %v", err)
				return c.Status(http.StatusInternalServerError).SendString("Internal Server Error")
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
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid cap token")
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
		Name:     "arkauthn",
		Value:    token,
		Expires:  expireAt,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		Domain:   "." + rootDomain,
	}
	c.Cookie(cookie)
	// 重定向
	if len(req.Redirect) > 0 {
		// 检查重定向URL是否安全 (Open Redirect Protection)
		safeRedirect := false
		if strings.HasPrefix(req.Redirect, "/") && !strings.HasPrefix(req.Redirect, "//") {
			safeRedirect = true
		} else {
			// 尝试解析 URL 获取 Hostname
			var hostname string
			u, err := url.Parse(req.Redirect)
			if err == nil {
				hostname = u.Hostname()
			}
			// 处理无协议头的 URL (如 //example.com)
			if hostname == "" && strings.HasPrefix(req.Redirect, "//") {
				if u, err := url.Parse("https:" + req.Redirect); err == nil {
					hostname = u.Hostname()
				}
			}

			if hostname != "" {
				// 1. 检查是否与认证服务属于同一根域名 (保持原有逻辑)
				redirectRoot, err := utils.ExtractRootDomain(req.Redirect)
				if err == nil && redirectRoot == rootDomain {
					safeRedirect = true
				}

				// 2. 检查 TrustedDomains (支持子域名匹配)
				if !safeRedirect {
					for _, domain := range vars.Config.TrustedDomains {
						// 允许完全相等 或 作为子域名 (e.g. "a.example.com" 匹配 "example.com")
						if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
							safeRedirect = true
							break
						}
					}
				}
			}
		}

		if safeRedirect {
			return c.Redirect(req.Redirect, fiber.StatusSeeOther)
		}
		logrus.Warnf("Invalid redirect attempt to %s", req.Redirect)
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
	var foundUser *vars.UserItem
	for _, u := range vars.Config.Users {
		if u.Username == username {
			// Create a copy to avoid referencing loop variable
			user := u
			foundUser = &user
			break
		}
	}

	if foundUser != nil {
		if strings.HasPrefix(foundUser.Password, "$2a$") || strings.HasPrefix(foundUser.Password, "$2b$") || strings.HasPrefix(foundUser.Password, "$2y$") {
			if bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(password)) == nil {
				return foundUser.Username, true
			}
		} else if subtle.ConstantTimeCompare([]byte(password), []byte(foundUser.Password)) > 0 {
			return foundUser.Username, true
		}
	} else {
		// Timing attack protection: simulate a bcrypt comparison
		bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
	}
	return "", false
}
