package utils

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zjyl1994/arkauthn/infra/vars"
)

var (
	// 错误定义
	ErrInvalidToken = errors.New("令牌无效")
	ErrExpiredToken = errors.New("令牌已过期")
)

// 自定义JWT声明结构
type Claims struct {
	Username string `json:"user"`
	jwt.RegisteredClaims
}

// GenerateToken 生成JWT令牌
// username: 用户名
// expireDuration: 过期时间，如果为0则使用默认过期时间(24小时)
func GenerateToken(username string, expireDuration time.Duration) (string, error) {
	// 如果未指定过期时间，默认24小时
	if expireDuration == 0 {
		expireDuration = 24 * time.Hour
	}

	// 设置JWT声明
	claims := Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expireDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	// 创建令牌
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 签名令牌
	secret, err := loadTokenSecretByUserName(username)
	if err != nil {
		return "", err
	}
	return token.SignedString(secret)
}

// ParseToken 解析JWT令牌
// 返回用户名、过期时间和错误信息
func ParseToken(tokenString string) (string, time.Time, error) {
	// 解析令牌
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		claims, ok := token.Claims.(*Claims)
		if !ok {
			return "", ErrInvalidToken
		}
		return loadTokenSecretByUserName(claims.Username)
	})

	if err != nil {
		// 检查是否是过期错误
		if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return "", time.Time{}, ErrExpiredToken
		}
		return "", time.Time{}, ErrInvalidToken
	}

	// 验证令牌
	if !token.Valid {
		return "", time.Time{}, ErrInvalidToken
	}

	// 获取声明
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", time.Time{}, ErrInvalidToken
	}

	// 获取过期时间
	expiresAt, err := claims.GetExpirationTime()
	if err != nil {
		return "", time.Time{}, ErrInvalidToken
	}

	return claims.Username, expiresAt.Time, nil
}

// ValidateToken 验证令牌是否有效
// 返回是否有效和错误信息
func ValidateToken(tokenString string) (bool, error) {
	_, _, err := ParseToken(tokenString)
	if err != nil {
		return false, err
	}
	return true, nil
}

func loadTokenSecretByUserName(username string) ([]byte, error) {
	for _, u := range vars.Config.Users {
		if u.Username == username {
			return []byte(u.Password), nil
		}
	}
	return nil, fmt.Errorf("用户 %s 不存在", username)
}
