package main

import (
	"regexp"
)

// 日志脱敏：把 Minecraft / Java 启动日志里常见的敏感信息打码，
// 避免 MC access token / session id / 邮箱 / 内网 IP 通过 Wails 事件
// 直接送到前端渲染。前端拿到的已经是脱敏后的文本。
var (
	rePrivateIP   = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)
	reAccessToken = regexp.MustCompile(`(?i)(access[_-]?token|session|token)=[A-Za-z0-9_\-\.]{16,}`)
	reEmail       = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reUUID        = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
)

// sanitizeLogLine 对单行日志做脱敏。命中即替换为 [REDACTED]。
func sanitizeLogLine(line string) string {
	line = reAccessToken.ReplaceAllString(line, `$1=[REDACTED]`)
	line = reEmail.ReplaceAllString(line, `[EMAIL]`)
	line = reUUID.ReplaceAllString(line, `[UUID]`)
	line = rePrivateIP.ReplaceAllString(line, `[LAN-IP]`)
	return line
}
