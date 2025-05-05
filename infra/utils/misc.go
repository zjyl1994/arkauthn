package utils

import (
	"crypto/sha256"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

func SHA256(input []byte) []byte {
	h := sha256.New()
	h.Write(input)
	return h.Sum(nil)
}

// ExtractRootDomain 从 URL 中提取根域名
// 例如：https://www.example.com/path -> example.com
// 如果是 IP 地址，则直接返回 IP 地址
func ExtractRootDomain(urlStr string) (string, error) {
	// 确保 URL 有协议前缀
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}

	// 解析 URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	// 获取主机名
	hostname := parsedURL.Hostname()
	
	// 检查是否为 IP 地址
	if ip := net.ParseIP(hostname); ip != nil {
		return hostname, nil
	}

	// 使用 publicsuffix 获取 eTLD+1（有效顶级域名加一级）
	domain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		return "", err
	}

	return domain, nil
}
