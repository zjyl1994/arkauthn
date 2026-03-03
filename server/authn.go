package server

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"github.com/zjyl1994/arkauthn/infra/utils"
	"github.com/zjyl1994/arkauthn/infra/vars"
	"golang.org/x/crypto/bcrypt"
)

var dummyBcryptHash []byte

func init() {
	dummyBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("dummy_password_for_timing_protection"), bcrypt.DefaultCost)
}

func forwardAuthHandler(c fiber.Ctx) error {
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
			return c.Redirect().Status(fiber.StatusSeeOther).To(u.String())
		} else {
			return c.SendStatus(http.StatusUnauthorized)
		}
	}
	c.Set("Remote-User", userinfo.Username)
	c.Set("X-Forwarded-User", userinfo.Username)
	logrus.Debugf("ForwardAuth success with user:%s", userinfo.Username)
	return c.SendStatus(http.StatusNoContent)
}

func loginAuthnHandler(c fiber.Ctx) error {
	var req struct {
		Username string `json:"username" form:"username"`
		Password string `json:"password" form:"password"`
		Redirect string `json:"redirect" form:"redirect"`
		CapToken string `json:"cap_token" form:"cap_token"`
		Duration int64  `json:"duration" form:"duration"`
	}
	err := c.Bind().Body(&req)
	if err != nil {
		return err
	}
	if len(req.Username) > 64 || len(req.Password) > 72 {
		return c.Status(http.StatusBadRequest).SendString("Invalid input length")
	}
	if vars.NodeRole == vars.NodeRoleReplica {
		return redirectToMaster(c, req.Redirect)
	}
	if req.CapToken == "" || !vars.CapInstance.ValidateToken(req.CapToken, false) {
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid cap token")
	}
	if req.Duration < 3600 || req.Duration > 31536000 {
		req.Duration = 3600
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
		return c.Redirect().Status(fiber.StatusFound).To(u.String())
	}
	// 生成JWT令牌
	dur := time.Duration(req.Duration) * time.Second
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
	domain := ""
	if net.ParseIP(rootDomain) == nil && rootDomain != "localhost" && strings.Contains(rootDomain, ".") {
		domain = "." + rootDomain
	}
	cookie := &fiber.Cookie{
		Name:     "arkauthn",
		Value:    token,
		Expires:  expireAt,
		HTTPOnly: true,
		Secure:   strings.HasPrefix(vars.Config.Redirect, "https") || c.Protocol() == "https",
		SameSite: "Lax",
		Domain:   domain,
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

				// 2. 检查 TrustedDomain (支持子域名匹配)
				if !safeRedirect {
					domain := vars.Config.TrustedDomain
					if domain != "" && (hostname == domain || strings.HasSuffix(hostname, "."+domain)) {
						safeRedirect = true
					}
				}
			}
		}

		if safeRedirect {
			return c.Redirect().Status(fiber.StatusSeeOther).To(req.Redirect)
		}
		logrus.Warnf("Invalid redirect attempt to %s", req.Redirect)
	}
	return c.Render("index", fiber.Map{
		"username": user,
		"expire":   expireAt.Unix(),
		"csrf":     ensureCsrfToken(c),
	})
}

func indexHandler(c fiber.Ctx) error {
	userinfo, ok := c.Locals(authUserKey).(authUserType)
	if !ok { // 没有登录
		if vars.NodeRole == vars.NodeRoleReplica {
			return c.Redirect().Status(fiber.StatusSeeOther).To(vars.Config.Redirect)
		}
		return c.Render("login", fiber.Map{})
	}
	return c.Render("index", fiber.Map{
		"username": userinfo.Username,
		"expire":   userinfo.Expire.Unix(),
		"csrf":     ensureCsrfToken(c),
	})
}

func tokenPageHandler(c fiber.Ctx) error {
	if vars.NodeRole == vars.NodeRoleReplica {
		return redirectToMaster(c, "/token")
	}
	userinfo, ok := c.Locals(authUserKey).(authUserType)
	if !ok {
		return c.Redirect().Status(fiber.StatusSeeOther).To("/")
	}
	return c.Render("token", fiber.Map{
		"username": userinfo.Username,
		"csrf":     ensureCsrfToken(c),
	})
}

func tokenGenerateHandler(c fiber.Ctx) error {
	if vars.NodeRole == vars.NodeRoleReplica {
		u, err := url.Parse(vars.Config.Redirect)
		if err != nil {
			return c.SendStatus(http.StatusNotFound)
		}
		u.Path = "/api/token"
		u.RawQuery = ""
		return c.Redirect().Status(fiber.StatusTemporaryRedirect).To(u.String())
	}
	userinfo, ok := c.Locals(authUserKey).(authUserType)
	if !ok {
		return c.SendStatus(http.StatusUnauthorized)
	}
	var req struct {
		Duration int64  `json:"duration" form:"duration"`
		CapToken string `json:"cap_token" form:"cap_token"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	if vars.AuthRateLimiter != nil && vars.AuthRateLimiter.IsLimited(c.IP()) {
		return c.Status(http.StatusTooManyRequests).SendString("Too many requests")
	}
	if req.CapToken == "" || !vars.CapInstance.ValidateToken(req.CapToken, false) {
		return c.Status(http.StatusUnauthorized).SendString("Invalid cap token")
	}
	if req.Duration == 0 {
		req.Duration = 3600
	}
	if req.Duration < 60 || req.Duration > 31536000 {
		return c.Status(http.StatusBadRequest).SendString("Invalid duration")
	}
	dur := time.Duration(req.Duration) * time.Second
	token, err := utils.GenerateToken(userinfo.Username, dur)
	if err != nil {
		return err
	}
	expireAt := time.Now().Add(dur)
	return c.JSON(fiber.Map{
		"token":     token,
		"expire_at": expireAt.Unix(),
	})
}

func logoutHandler(c fiber.Ctx) error {
	csrfToken := c.FormValue("csrf_token")
	cookieToken := c.Cookies("arkauthn_csrf")
	if csrfToken == "" || cookieToken == "" || subtle.ConstantTimeCompare([]byte(csrfToken), []byte(cookieToken)) != 1 {
		return c.SendStatus(http.StatusUnauthorized)
	}
	rootDomain, err := utils.ExtractRootDomain(vars.Config.Redirect)
	if err != nil {
		c.ClearCookie("arkauthn")
		c.ClearCookie("arkauthn_csrf")
		return c.Render("logout", fiber.Map{})
	}
	domain := ""
	if net.ParseIP(rootDomain) == nil && rootDomain != "localhost" && strings.Contains(rootDomain, ".") {
		domain = "." + rootDomain
	}
	c.Cookie(&fiber.Cookie{
		Name:     "arkauthn",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HTTPOnly: true,
		Secure:   strings.HasPrefix(vars.Config.Redirect, "https") || c.Protocol() == "https",
		SameSite: "Lax",
		Domain:   domain,
	})
	c.Cookie(&fiber.Cookie{
		Name:     "arkauthn_csrf",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HTTPOnly: true,
		Secure:   strings.HasPrefix(vars.Config.Redirect, "https") || c.Protocol() == "https",
		SameSite: "Lax",
		Domain:   domain,
	})
	return c.Render("logout", fiber.Map{})
}

func checkUser(username, password string) (string, bool) {
	var foundUser *vars.UserItem
	for i := range vars.Users {
		u := &vars.Users[i]
		if u.Username == username {
			foundUser = u
			break
		}
	}

	if foundUser != nil {
		if strings.HasPrefix(foundUser.Password, "$2a$") || strings.HasPrefix(foundUser.Password, "$2b$") || strings.HasPrefix(foundUser.Password, "$2y$") {
			if bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(password)) == nil {
				return foundUser.Username, true
			}
		} else {
			if subtle.ConstantTimeCompare([]byte(foundUser.Password), []byte(password)) == 1 {
				return foundUser.Username, true
			}
			bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
		}
	} else {
		// Timing attack protection: simulate a bcrypt comparison
		bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
	}
	return "", false
}

func publicConfigHandler(c fiber.Ctx) error {
	if vars.NodeRole == vars.NodeRoleReplica {
		return c.SendStatus(http.StatusNotFound)
	}
	return c.JSON(vars.PublicConfig{
		Redirect:         vars.Config.Redirect,
		Ed25519PublicKey: base64.StdEncoding.EncodeToString(vars.Ed25519PublicKey),
	})
}

func redirectToMaster(c fiber.Ctx, redirect string) error {
	u, err := url.Parse(vars.Config.Redirect)
	if err != nil {
		return err
	}
	q := u.Query()
	if redirect != "" {
		q.Set("r", redirect)
	}
	u.RawQuery = q.Encode()
	return c.Redirect().Status(fiber.StatusSeeOther).To(u.String())
}

func ensureCsrfToken(c fiber.Ctx) string {
	token := c.Cookies("arkauthn_csrf")
	if token != "" {
		return token
	}
	token = utils.RandString(32)
	rootDomain, err := utils.ExtractRootDomain(vars.Config.Redirect)
	domain := ""
	if err == nil && net.ParseIP(rootDomain) == nil && rootDomain != "localhost" && strings.Contains(rootDomain, ".") {
		domain = "." + rootDomain
	}
	c.Cookie(&fiber.Cookie{
		Name:     "arkauthn_csrf",
		Value:    token,
		HTTPOnly: true,
		Secure:   strings.HasPrefix(vars.Config.Redirect, "https") || c.Protocol() == "https",
		SameSite: "Lax",
		Domain:   domain,
	})
	return token
}
