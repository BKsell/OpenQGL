package main

// resurlguard.go —— 服务器下发资源包（server-resource-pack）URL 出站策略内核。
//
// MC 服务器可以在玩家进服时强制要求客户端从它给的 URL 下载资源包。这个 URL
// 由不可信服务器提供，直接交给下载器就是一个“服务器让启动器替它访问任意地址”
// 的面：攻击者可指内网地址、超大文件、或带 userinfo 的链接。策略：
//
//   - 必须 https；
//   - 拒绝 user:pass@、拒绝 IP 字面量；
//   - 不做域名白名单（资源包本来就来自各家服务器），但记录 host 交给配额层；
//   - 仅判定，不下载。

import (
	"net/url"
	"strings"
)

// ResDecision 是一次资源包 URL 判定。
type ResDecision struct {
	Allow bool
	Why   string
	Host  string
	// SizeHintBytes 是从 URL 带不出大小时为 0，由下载器自己 enforce 配额。
	SizeHintBytes int64
}

// classifyResPackURL 判定服务器下发的资源包 URL。
func classifyResPackURL(raw string) ResDecision {
	if strings.TrimSpace(raw) == "" {
		return ResDecision{Allow: false, Why: "empty url"}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ResDecision{Allow: false, Why: "parse error"}
	}
	if strings.ToLower(u.Scheme) != "https" {
		return ResDecision{Allow: false, Why: "scheme must be https", Host: u.Hostname()}
	}
	if u.User != nil {
		return ResDecision{Allow: false, Why: "userinfo not allowed", Host: u.Hostname()}
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ResDecision{Allow: false, Why: "empty host"}
	}
	if isIPLiteralHost(host) {
		return ResDecision{Allow: false, Why: "ip literal rejected", Host: host}
	}
	return ResDecision{Allow: true, Why: "https clean host", Host: host}
}

// allowResPackDownload 便捷布尔入口。
func allowResPackDownload(raw string) bool {
	return classifyResPackURL(raw).Allow
}
