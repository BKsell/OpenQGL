package main

// redirectltdguard.go —— OAuth 回跳 redirect_uri 与登录后跳转的受限开放重定向守卫。
//
// 背景：
//   启动器做微软/Mojang/Yggdrasil 登录时要携带 redirect_uri，登录完成后还要按服务端给的
//   "下一步地址"跳转/打开浏览器。若回跳地址不做客户端绑定与协议约束，会出现：
//     - 开放重定向：把用户从可信登录域名引到钓鱼站，并在 Referer 里带 code；
//     - 授权码/令牌经 URL fragment 或查询串泄露给攻击者控制的回跳主机；
//     - redirect_uri 指向 localhost/内网元数据地址，被本机恶意服务或云元端点截走 code；
//     - 协议相对、反斜杠混淆、userinfo 段仿冒（https://client@evil）；
//     - 通配后缀绕过：注册 "https://client.test" 却允许 "https://client.test.evil"。
//   本模块对"已注册客户端允许的回跳来源"做精确匹配（scheme+host+port+路径前缀），
//   纯字节解析，不使用正则。

import (
	"strings"
)

const (
	RLDReasonEmpty            = "rld-empty-target"
	RLDReasonNonHTTPScheme    = "rld-non-http-scheme"
	RLDReasonProtocolRelative = "rld-protocol-relative"
	RLDReasonBackslashHost    = "rld-backslash-host"
	RLDReasonUserInfo         = "rld-userinfo-spoof"
	RLDReasonHostNotAllowed   = "rld-host-not-allowlisted"
	RLDReasonPathPrefixDenied = "rld-path-prefix-denied"
	RLDReasonLocalOrMetadata  = "rld-loopback-or-metadata-target"
	RLDReasonFragmentOrQuery  = "rld-fragment-query-with-code-risk"
	RLDReasonControlChar      = "rld-control-char"
)

// RLDClient 描述一个已注册 OAuth 客户端允许的回跳目标。
type RLDClient struct {
	ClientID      string
	AllowedHosts  map[string]bool // 小写 host（含端口）精确白名单
	PathPrefixes  []string        // 允许的路径前缀（至少一个，'/' 表示不限）
	AllowLoopback bool            // 是否允许 http://127.0.0.1 / localhost（原生客户端 loopback 流）
}

// RLDPolicy 控制额外限制。
type RLDPolicy struct {
	RejectMetadataTargets bool // 169.254.169.254 / metadata.google.internal
	RejectFragmentRisk    bool // 回跳带 # 时提示 fragment 不会上送但易混淆
	RejectControlChars    bool
}

// RLDFinding 记录一处回跳风险。
type RLDFinding struct {
	Reason string
	Detail string
}

// DefaultRLDPolicy 返回默认策略。
func DefaultRLDPolicy() RLDPolicy {
	return RLDPolicy{RejectMetadataTargets: true, RejectFragmentRisk: false, RejectControlChars: true}
}

type rldURL struct {
	scheme        string
	host          string // 小写，含端口
	port          string
	path          string
	query         string
	fragment      string
	hasUserInfo   bool
	protoRelative bool
}

func rldControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x1F || c == 0x7F {
			return true
		}
	}
	return false
}

// rldParse 解析 http(s) 回跳 URL，识别协议相对/反斜杠/userinfo 等混淆。
func rldParse(raw string) (rldURL, bool) {
	u := rldURL{}
	s := strings.TrimSpace(raw)
	if s == "" {
		return u, false
	}
	rest := s
	if strings.HasPrefix(rest, "//") || strings.HasPrefix(rest, `\/`) {
		u.protoRelative = true
		rest = rest[2:]
	} else {
		colon := strings.IndexByte(rest, ':')
		slash := strings.IndexByte(rest, '/')
		if colon > 0 && (slash < 0 || colon < slash) {
			u.scheme = strings.ToLower(rest[:colon])
			rest = rest[colon+1:]
			if strings.HasPrefix(rest, "//") {
				rest = rest[2:]
			}
		}
	}
	// fragment
	if h := strings.IndexByte(rest, '#'); h >= 0 {
		u.fragment = rest[h+1:]
		rest = rest[:h]
	}
	// query
	if q := indexByteRLD(rest, '?'); q >= 0 {
		u.query = rest[q+1:]
		rest = rest[:q]
	}
	// userinfo
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		slashBefore := strings.IndexByte(rest[:at], '/')
		if slashBefore < 0 {
			u.hasUserInfo = true
			rest = rest[at+1:]
		}
	}
	u.path = "/"
	if len(rest) > 0 {
		if rest[0] == '\\' {
			rest = "/" + rest[1:]
			u.protoRelative = true
		}
		sl := indexByteRLD(rest, '/')
		if sl < 0 {
			u.host = strings.ToLower(rest)
			u.path = "/"
		} else {
			u.host = strings.ToLower(rest[:sl])
			u.path = rest[sl:]
		}
	}
	if hc := strings.IndexByte(u.host, ':'); hc >= 0 {
		u.port = u.host[hc+1:]
	}
	return u, true
}

func indexByteRLD(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// rldIsLoopback 判断 host 是否回环/本机。
func rldIsLoopback(host string) bool {
	h := strings.ToLower(host)
	h = strings.TrimPrefix(h, "[")
	if idx := strings.IndexByte(h, ']'); idx >= 0 {
		h = h[:idx]
	}
	if colon := indexByteRLD(h, ':'); colon >= 0 {
		h = h[:colon]
	}
	switch h {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return strings.HasPrefix(h, "127.")
}

// rldIsMetadata 判断是否云元数据/链路本地地址。
func rldIsMetadata(host string) bool {
	h := strings.ToLower(host)
	if colon := indexByteRLD(h, ':'); colon >= 0 {
		h = h[:colon]
	}
	if h == "169.254.169.254" || h == "metadata.google.internal" || h == "metadata" {
		return true
	}
	return strings.HasPrefix(h, "169.254.") || strings.HasPrefix(h, "fe80:")
}

func rldPathAllowed(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "/" {
			return true
		}
		if path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") ||
			strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// RLDValidate 校验回跳 URL 是否属于该客户端注册范围。
func RLDValidate(rawURL string, client RLDClient, policy RLDPolicy) (safe bool, findings []RLDFinding) {
	if strings.TrimSpace(rawURL) == "" {
		return false, []RLDFinding{{Reason: RLDReasonEmpty}}
	}
	if policy.RejectControlChars && rldControl(rawURL) {
		findings = append(findings, RLDFinding{Reason: RLDReasonControlChar})
	}
	u, ok := rldParse(rawURL)
	if !ok {
		return false, append(findings, RLDFinding{Reason: RLDReasonEmpty})
	}
	if u.protoRelative {
		reason := RLDReasonProtocolRelative
		if strings.Contains(rawURL, `\`) {
			reason = RLDReasonBackslashHost
		}
		findings = append(findings, RLDFinding{Reason: reason})
	}
	if u.hasUserInfo {
		findings = append(findings, RLDFinding{Reason: RLDReasonUserInfo})
	}
	if u.scheme != "" && u.scheme != "http" && u.scheme != "https" {
		findings = append(findings, RLDFinding{Reason: RLDReasonNonHTTPScheme, Detail: u.scheme})
	}
	// loopback
	isLoop := rldIsLoopback(u.host)
	if isLoop && !client.AllowLoopback {
		findings = append(findings, RLDFinding{Reason: RLDReasonLocalOrMetadata, Detail: "loopback"})
	}
	if policy.RejectMetadataTargets && rldIsMetadata(u.host) {
		findings = append(findings, RLDFinding{Reason: RLDReasonLocalOrMetadata, Detail: "metadata"})
	}
	// host 白名单精确匹配（防止后缀绕过）
	if !client.AllowedHosts[u.host] {
		findings = append(findings, RLDFinding{Reason: RLDReasonHostNotAllowed, Detail: u.host})
	}
	// 非 loopback 的 http 回跳视为不安全（元数据之外仍可能被劫持 code）
	if !isLoop && u.scheme == "http" {
		findings = append(findings, RLDFinding{Reason: RLDReasonNonHTTPScheme, Detail: "http-callback"})
	}
	if len(client.PathPrefixes) > 0 && !rldPathAllowed(u.path, client.PathPrefixes) {
		findings = append(findings, RLDFinding{Reason: RLDReasonPathPrefixDenied, Detail: u.path})
	}
	if policy.RejectFragmentRisk && u.fragment != "" {
		findings = append(findings, RLDFinding{Reason: RLDReasonFragmentOrQuery})
	}
	return len(findings) == 0, findings
}
