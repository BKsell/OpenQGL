package main

// proxyenvguard.go —— 出向代理环境变量（HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY）投毒守卫。
//
// 背景：
//   Go 的 http.Transport 默认读取 HTTP_PROXY/HTTPS_PROXY/ALL_PROXY 决定出向代理，并读
//   NO_PROXY 决定哪些主机绕过代理。启动器、JVM 下载子进程也会继承这些变量。风险：
//     1. 恶意软件 / 被篡改的启动脚本把 HTTP_PROXY 指向本地或内网攻击者，透明截获 Mojang
//        登录令牌、皮肤站 Cookie、下载流量（中间人，即便 HTTPS 也可能被引导装根证书）；
//     2. 代理 URI 里内嵌 userinfo（http://attacker:pass@host），凭据在进程环境 / 崩溃转储
//        / 错误信息里泄露；
//     3. NO_PROXY 被设成 '*' 或过宽后缀，让本应走企业审计代理的敏感直连绕过监控，或反向
//        把内部地址错误地送进外部代理；
//     4. ALL_PROXY 指向 socks5h:// 做 DNS 远程解析，绕过本地 SSRF / rebinding 防护；
//     5. file://、socks 到环回 / 私网。
//
// 纯字符解析，不使用正则。

const (
	PXEReasonProxyToPrivate   = "pxe-proxy-target-private-or-loopback"
	PXEReasonEmbeddedCreds    = "pxe-proxy-uri-embedded-userinfo"
	PXEReasonDangerousScheme  = "pxe-proxy-dangerous-scheme"
	PXEReasonNoProxyWildcard  = "pxe-no-proxy-wildcard-bypass"
	PXEReasonNoProxyOverbroad = "pxe-no-proxy-overbroad-suffix"
	PXEReasonBadURI           = "pxe-proxy-uri-malformed"
	PXEReasonControlChar      = "pxe-proxy-value-control-character"
)

// PXEPolicy 控制代理变量校验。
type PXEPolicy struct {
	AllowEmbeddedCredentials bool
	AllowPrivateProxy        bool
	AllowedSchemes           []string
	BlockNoProxyWildcard     bool
}

// PXEFinding 记录一处代理风险。
type PXEFinding struct {
	Reason string
	Var    string
	Value  string
	Detail string
}

// DefaultPXEPolicy 返回默认严格策略。
func DefaultPXEPolicy() PXEPolicy {
	return PXEPolicy{
		AllowEmbeddedCredentials: false,
		AllowPrivateProxy:        false,
		AllowedSchemes:           []string{"http", "https", "socks5", "socks"},
		BlockNoProxyWildcard:     true,
	}
}

// pxeLowerASCII 归一小写。
func pxeLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// pxeHasControlChar 检测控制字符。
func pxeHasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// pxeScheme 取 scheme（小写），无冒号返回空。
func pxeScheme(uri string) string {
	for i := 0; i < len(uri); i++ {
		c := uri[i]
		if c == ':' {
			return pxeToLower(uri[:i])
		}
		if c == '/' || c == '?' || c == '#' {
			return ""
		}
	}
	return ""
}

func pxeToLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = pxeLowerASCII(s[i])
	}
	return string(b)
}

// pxeSchemeAllowed 判断 scheme 是否在白名单。
func pxeSchemeAllowed(scheme string, allowed []string) bool {
	for _, a := range allowed {
		if scheme == a {
			return true
		}
	}
	return false
}

// pxeStripScheme 去掉 "scheme://" 前缀，返回剩余部分。
func pxeStripScheme(uri string) string {
	i := 0
	for i < len(uri) && uri[i] != ':' {
		i++
	}
	rest := uri[i:]
	rest = pxeTrimPrefix(rest, "://")
	return rest
}

func pxeTrimPrefix(s, p string) string {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

// pxeAuthority 取到路径 / 查询 / 片段之前的 authority。
func pxeAuthority(rest string) string {
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' || rest[i] == '?' || rest[i] == '#' {
			end = i
			break
		}
	}
	return rest[:end]
}

// pxeHostPort 从 authority 拆 host 与 port；处理 userinfo@ 与 IPv6 [::1]。
func pxeHostPort(authority string) (host, userinfo string, ok bool) {
	// userinfo = 最后一个 '@' 之前。
	at := -1
	for i := 0; i < len(authority); i++ {
		if authority[i] == '@' {
			at = i
		}
	}
	hp := authority
	if at >= 0 {
		userinfo = authority[:at]
		hp = authority[at+1:]
	}
	if hp == "" {
		return "", userinfo, false
	}
	// IPv6 字面量。
	if hp[0] == '[' {
		cb := -1
		for i := 1; i < len(hp); i++ {
			if hp[i] == ']' {
				cb = i
				break
			}
		}
		if cb < 0 {
			return "", userinfo, false
		}
		return hp[:cb+1], userinfo, true
	}
	// host[:port]：去掉最后一个冒号后的端口（仅当冒号后纯数字）。
	colon := -1
	for i := 0; i < len(hp); i++ {
		if hp[i] == ':' {
			colon = i
		}
	}
	if colon >= 0 {
		port := hp[colon+1:]
		allDigit := len(port) > 0
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				allDigit = false
				break
			}
		}
		if allDigit {
			hp = hp[:colon]
		}
	}
	return hp, userinfo, true
}

// PXEEvaluateProxy 校验一个 *_PROXY 变量值。
func PXEEvaluateProxy(varName, value string, pol PXEPolicy) []PXEFinding {
	var out []PXEFinding
	if value == "" {
		return out
	}
	add := func(reason, detail string) {
		out = append(out, PXEFinding{Reason: reason, Var: varName, Value: value, Detail: detail})
	}
	if pxeHasControlChar(value) {
		add(PXEReasonControlChar, "")
	}
	scheme := pxeScheme(value)
	if scheme == "" {
		add(PXEReasonBadURI, "missing-scheme")
		return out
	}
	if scheme == "file" {
		add(PXEReasonDangerousScheme, scheme)
	}
	if !pxeSchemeAllowed(scheme, pol.AllowedSchemes) {
		add(PXEReasonDangerousScheme, scheme)
	}
	authority := pxeAuthority(pxeStripScheme(value))
	host, userinfo, ok := pxeHostPort(authority)
	if !ok {
		add(PXEReasonBadURI, "bad-authority")
		return out
	}
	if userinfo != "" && !pol.AllowEmbeddedCredentials {
		add(PXEReasonEmbeddedCreds, "")
	}
	if !pol.AllowPrivateProxy && pxeHostIsPrivate(host) {
		add(PXEReasonProxyToPrivate, host)
	}
	return out
}

// pxeHostIsPrivate 复用 DNS 分类：去 IPv6 方括号后判环回 / 私网 / 链路本地 / 元数据。
func pxeHostIsPrivate(host string) bool {
	h := host
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	if cls, ok := drgClassifyIP(h); ok {
		return cls != DRGClassPublic
	}
	// 字面 localhost 及其它保留名。
	low := pxeToLower(h)
	if low == "localhost" || low == "localhost.localdomain" || low == "ip6-localhost" {
		return true
	}
	if low == "metadata.google.internal" || low == "169.254.169.254" {
		return true
	}
	return false
}

// PXEEvaluateNoProxy 校验 NO_PROXY 值。
func PXEEvaluateNoProxy(value string, pol PXEPolicy) []PXEFinding {
	var out []PXEFinding
	if value == "" {
		return out
	}
	add := func(reason, detail string) {
		out = append(out, PXEFinding{Reason: reason, Var: "NO_PROXY", Value: value, Detail: detail})
	}
	entries := pxeSplitList(value)
	for _, e := range entries {
		entry := pxeTrimSpacePXE(e)
		if entry == "*" {
			if pol.BlockNoProxyWildcard {
				add(PXEReasonNoProxyWildcard, "")
			}
			continue
		}
		// 顶级后缀（如 "com"、"cn"）或单标签会让几乎所有站点绕过代理。
		if pxeLooksTLD(entry) {
			add(PXEReasonNoProxyOverbroad, entry)
		}
	}
	return out
}

// pxeSplitList 以逗号分隔。
func pxeSplitList(s string) []string {
	out := []string{}
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	out = append(out, cur)
	return out
}

func pxeTrimSpacePXE(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}

// pxeLooksTLD 判断条目是否只是顶级后缀 / 过宽。
func pxeLooksTLD(entry string) bool {
	e := pxeToLower(entry)
	if len(e) > 0 && e[0] == '.' {
		e = e[1:]
	}
	if e == "" {
		return false
	}
	dot := -1
	for i := 0; i < len(e); i++ {
		if e[i] == '.' {
			dot = i
		}
	}
	// 不含点，且是 2~6 字母的常见顶级，判过宽（如 com、cn、net）。
	if dot < 0 {
		if len(e) >= 2 && len(e) <= 6 {
			allAlpha := true
			for i := 0; i < len(e); i++ {
				c := e[i]
				if !((c >= 'a' && c <= 'z')) {
					allAlpha = false
					break
				}
			}
			return allAlpha
		}
	}
	return false
}

// PXEIsSafe 便捷判定：同时校验代理与 NO_PROXY。
func PXEIsSafe(proxy, noProxy string) bool {
	pol := DefaultPXEPolicy()
	if len(PXEEvaluateProxy("HTTPS_PROXY", proxy, pol)) != 0 {
		return false
	}
	if len(PXEEvaluateNoProxy(noProxy, pol)) != 0 {
		return false
	}
	return true
}
