package main

// urluserinfoguard.go —— URL 中内嵌 userinfo（scheme://user:pass@host）凭据泄露守卫。
//
// 背景：
//   下载 / 更新 URL 若内嵌用户名密码（https://user:token@host/path），凭据会在多处被动泄露：
//     1. 拼进日志、错误信息、User-Agent 之外的排障输出；
//     2. 跟随跨主机重定向时被转发给第三方；
//     3. 出现在进程命令行 / 崩溃转储 / 系统代理记录里；
//     4. 历史上浏览器与 HTTP 库对 userinfo 的处理不一致，有的会用它做 HTTP Basic 认证，
//        用户只看到 host，形成"看不见的凭据被发送"。
//   启动器的下载源、整合包清单、BMCSAPI 地址都来自外部配置，需要在"把 URL 交给 HTTP 客户端
//   或写入日志"之前剥离 / 拒绝内嵌凭据，并提供安全展示形态。
//
// 纯字符解析，不使用正则。

const (
	UIReasonEmbeddedCredentials = "ui-url-embedded-userinfo"
	UIReasonPasswordPresent     = "ui-url-embedded-password"
	UIReasonBadAuthority        = "ui-url-malformed-authority"
	UIReasonControlChar         = "ui-url-control-character"
	UIReasonDangerousScheme     = "ui-url-dangerous-scheme"
)

// UIPolicy 控制 URL 校验严格度。
type UIPolicy struct {
	RejectAnyUserInfo  bool // 即使只有用户名也拒绝（默认 true）
	AllowedSchemes     []string
	BlockControlChars  bool
}

// UIFinding 记录一处 URL 风险。
type UIFinding struct {
	Reason string
	URL    string
	Detail string
}

// UIParts 是解析后的 URL 视图（仅安全相关字段）。
type UIParts struct {
	Scheme   string
	Username string
	Password string
	HasAuth  bool
	Host     string
	Port     string
	Path     string
}

// DefaultUIPolicy 返回默认严格策略。
func DefaultUIPolicy() UIPolicy {
	return UIPolicy{
		RejectAnyUserInfo: true,
		AllowedSchemes:    []string{"http", "https"},
		BlockControlChars: true,
	}
}

// uiLowerASCII 归一小写。
func uiLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func uiToLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = uiLowerASCII(s[i])
	}
	return string(b)
}

// UIParse 纯字符拆解 URL：scheme://[user[:pass]@]host[:port][/path][?query][#frag]。
func UIParse(raw string) (UIParts, bool) {
	var p UIParts
	colon := -1
	for i := 0; i < len(raw); i++ {
		if raw[i] == ':' {
			colon = i
			break
		}
		if raw[i] == '/' || raw[i] == '?' || raw[i] == '#' {
			return p, false
		}
	}
	if colon < 0 {
		return p, false
	}
	p.Scheme = uiToLower(raw[:colon])
	rest := raw[colon+1:]
	if len(rest) < 2 || rest[0] != '/' || rest[1] != '/' {
		// 无 authority（mailto 等），本守卫只关心带主机的层级 URL。
		return p, false
	}
	authAndPath := rest[2:]
	// authority 在第一个 / ? # 处结束。
	authEnd := len(authAndPath)
	for i := 0; i < len(authAndPath); i++ {
		c := authAndPath[i]
		if c == '/' || c == '?' || c == '#' {
			authEnd = i
			break
		}
	}
	authority := authAndPath[:authEnd]
	p.Path = authAndPath[authEnd:]

	// userinfo。
	at := -1
	for i := 0; i < len(authority); i++ {
		if authority[i] == '@' {
			at = i
		}
	}
	hostPort := authority
	if at >= 0 {
		p.HasAuth = true
		userinfo := authority[:at]
		hostPort = authority[at+1:]
		pc := -1
		for i := 0; i < len(userinfo); i++ {
			if userinfo[i] == ':' {
				pc = i
				break
			}
		}
		if pc >= 0 {
			p.Username = userinfo[:pc]
			p.Password = userinfo[pc+1:]
		} else {
			p.Username = userinfo
		}
	}

	// host / port，处理 IPv6 方括号。
	if len(hostPort) >= 2 && hostPort[0] == '[' {
		cb := -1
		for i := 1; i < len(hostPort); i++ {
			if hostPort[i] == ']' {
				cb = i
				break
			}
		}
		if cb < 0 {
			return p, false
		}
		p.Host = hostPort[1:cb]
		tail := hostPort[cb+1:]
		if len(tail) > 0 && tail[0] == ':' {
			p.Port = tail[1:]
		}
	} else {
		pc := -1
		for i := 0; i < len(hostPort); i++ {
			if hostPort[i] == ':' {
				pc = i
			}
		}
		if pc >= 0 {
			p.Host = hostPort[:pc]
			p.Port = hostPort[pc+1:]
		} else {
			p.Host = hostPort
		}
	}
	if p.Host == "" {
		return p, false
	}
	return p, true
}

// uiSchemeAllowed 判断 scheme 是否允许。
func uiSchemeAllowed(s string, allowed []string) bool {
	for _, a := range allowed {
		if s == a {
			return true
		}
	}
	return false
}

func uiHasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// UIEvaluate 校验一个待使用 / 展示 / 落日志的 URL。
func UIEvaluate(raw string, pol UIPolicy) []UIFinding {
	var out []UIFinding
	add := func(reason, detail string) {
		out = append(out, UIFinding{Reason: reason, URL: raw, Detail: detail})
	}
	if pol.BlockControlChars && uiHasControlChar(raw) {
		add(UIReasonControlChar, "")
	}
	p, ok := UIParse(raw)
	if !ok {
		add(UIReasonBadAuthority, "")
		return out
	}
	if !uiSchemeAllowed(p.Scheme, pol.AllowedSchemes) {
		add(UIReasonDangerousScheme, p.Scheme)
	}
	if p.HasAuth {
		if pol.RejectAnyUserInfo {
			add(UIReasonEmbeddedCredentials, "")
		}
		if p.Password != "" {
			add(UIReasonPasswordPresent, "")
		}
	}
	return out
}

// UIStripUserInfo 返回去掉 userinfo 的安全 URL（保留 scheme/host/port/path）。
func UIStripUserInfo(raw string) (string, bool) {
	p, ok := UIParse(raw)
	if !ok {
		return raw, false
	}
	out := p.Scheme + "://"
	host := p.Host
	// IPv6 重新加方括号。
	if uiLooksV6(host) {
		host = "[" + host + "]"
	}
	out += host
	if p.Port != "" {
		out += ":" + p.Port
	}
	out += p.Path
	return out, true
}

// uiLooksV6 粗略判断 host 是否为 IPv6 字面量（含冒号）。
func uiLooksV6(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] == ':' {
			return true
		}
	}
	return false
}

// UISafeDisplay 返回用于日志 / 界面展示的 URL：存在凭据时打码。
func UISafeDisplay(raw string) string {
	p, ok := UIParse(raw)
	if !ok {
		return raw
	}
	if !p.HasAuth {
		return raw
	}
	out := p.Scheme + "://"
	if p.Username != "" {
		out += "***"
	}
	if p.Password != "" {
		out += ":***"
	}
	out += "@"
	host := p.Host
	if uiLooksV6(host) {
		host = "[" + host + "]"
	}
	out += host
	if p.Port != "" {
		out += ":" + p.Port
	}
	out += p.Path
	return out
}

// UIIsSafe 便捷判定。
func UIIsSafe(raw string) bool {
	return len(UIEvaluate(raw, DefaultUIPolicy())) == 0
}
