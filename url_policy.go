package main

import (
	"fmt"
	"net/url"
	"strings"
)

// 外部链接白名单：启动器里凡是从远程元数据（mod 页、更新日志、皮肤站）
// 拿到 URL 后要交给系统浏览器打开的，必须先过这里。
// 防止被恶意 mod 元数据塞 javascript: / file: / 内网地址等。
var allowedExternalHosts = map[string]bool{
	"www.minecraft.net":   true,
	"minecraft.net":       true,
	"account.mojang.com": true,
	"authserver.mojang.com": true,
	"api.mojang.com":      true,
	"libraries.minecraft.net": true,
	"piston-data.mojang.com": true,
	"cdn.modrinth.com":    true,
	"api.modrinth.com":    true,
	"modrinth.com":        true,
	"www.curseforge.com":  true,
	"curseforge.com":      true,
	"github.com":          true,
	"raw.githubusercontent.com": true,
	"objects.githubusercontent.com": true,
	"maven.fabricmc.net":  true,
	"maven.fabricmc.net":  true,
	"piston-meta.mojang.com": true,
	"bmclapi2.bangbang93.com": true,
}

// safeExternalURL 校验 url 是否允许交给系统浏览器打开。
// 只允许 https，host 必须在白名单内。
func safeExternalURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("空 URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("URL 解析失败: %v", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("只允许 https:// 链接，收到 %q", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if !allowedExternalHosts[host] {
		return fmt.Errorf("host %q 不在外部链接白名单内", host)
	}
	return nil
}