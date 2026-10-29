package main

// serverfaviconguard.go —— 服务器列表 ping 回来的 favicon URL 校验。
//
// MC 服务器列表 ping 响应里带一个 favicon 字段（data:image/png;base64 或
// 一个 URL）。如果允许 URL 形式，启动器去抓它就等于对内网/任意主机发请求
// （SSRF），还会把用户 IP 暴露给恶意服务器。这里把"这个 favicon 该不该被
// 启动器请求/接受"收敛成纯函数。

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// maxServerFaviconBytes 内联 favicon 的硬上限。
const maxServerFaviconBytes = 1024 * 64

// ValidateServerFavicon 校验 favicon 字段。
// 只接受 data:image/png;base64 形式；其他一律拒绝。
// 返回 (cleanedBase64, error)。
func ValidateServerFavicon(field string) (string, error) {
	f := strings.TrimSpace(field)
	if f == "" {
		return "", nil
	}
	if !strings.HasPrefix(f, "data:image/png;base64,") {
		return "", fmt.Errorf("favicon must be data:image/png;base64")
	}
	raw := strings.TrimPrefix(f, "data:image/png;base64,")
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("favicon base64: %w", err)
	}
	if len(decoded) == 0 {
		return "", fmt.Errorf("empty favicon payload")
	}
	if len(decoded) > maxServerFaviconBytes {
		return "", fmt.Errorf("favicon too large: %d bytes", len(decoded))
	}
	return raw, nil
}

// ValidateServerFaviconURL 校验外部 favicon URL（未来若支持）。
// 仅允许 https，且不允许内网/回环主机。
func ValidateServerFaviconURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("empty favicon url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("bad favicon url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("favicon url must be https")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("empty favicon host")
	}
	if isLoopbackOrPrivateHost(host) {
		return fmt.Errorf("favicon host is private: %s", host)
	}
	return nil
}
