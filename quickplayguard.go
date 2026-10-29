package main

// quickplayguard.go —— Quick Play 直连参数校验。
//
// MC 1.20+ 支持从启动器直接 `--quickPlaySingleplayer <world>` /
// `--quickPlayMultiplayer <host:port>` / `--quickPlayRealms <id>`。这些字符串由用户
// 或外部链接（deeplink/快捷方式）传入，直接拼到 JVM 参数上有注入风险。
// 这里只做“这个值能不能安全塞进命令行参数”的判定，不解析真实联机。

import (
	"fmt"
	"net"
	"strings"
)

// QuickPlayTarget 是一次 Quick Play 目标。
type QuickPlayTarget struct {
	Mode string // singleplayer / multiplayer / realms
	Arg  string
}

// ValidateQuickPlayArg 按模式校验 Quick Play 参数。
func ValidateQuickPlayArg(mode, arg string) error {
	a := strings.TrimSpace(arg)
	if a == "" {
		return fmt.Errorf("empty quickplay arg")
	}
	if strings.ContainsAny(a, "\r\n") {
		return fmt.Errorf("newline in quickplay arg")
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "singleplayer":
		// 存档名只允许安全字符，禁止路径穿越。
		if strings.ContainsAny(a, `/\:*?"<>|`) || strings.Contains(a, "..") {
			return fmt.Errorf("unsafe world name: %q", a)
		}
	case "multiplayer":
		host, port, err := net.SplitHostPort(a)
		if err != nil {
			// 允许只给主机，默认 25565。
			host = a
			port = "25565"
		}
		host = strings.Trim(host, "[]")
		if host == "" || strings.Contains(host, "..") {
			return fmt.Errorf("bad mp host: %q", a)
		}
		if port != "" {
			p, err := net.LookupPort("tcp", port)
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("bad port: %q", port)
			}
		}
	case "realms":
		if strings.ContainsAny(a, "/\\?&") {
			return fmt.Errorf("bad realms id: %q", a)
		}
	default:
		return fmt.Errorf("unknown quickplay mode: %q", mode)
	}
	return nil
}

// AllowQuickplay 便捷布尔入口。
func AllowQuickplay(mode, arg string) bool {
	return ValidateQuickPlayArg(mode, arg) == nil
}
