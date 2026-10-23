package main

// ssrfredirectguard.go —— 下载 / API 请求跟随重定向时的 SSRF 与协议降级守卫。
//
// 背景：
//   启动器会跟随 3xx 重定向下载版本清单、整合包、皮肤资源。很多 SSRF 防线只校验"第一个
//   URL"，但攻击者可以让公网 URL 返回 302 Location: http://127.0.0.1/、file:///、
//   http://169.254.169.254/ 或 gopher://，于是跟随逻辑把请求带进内网 / 云元数据 / 本地
//   文件；跨主机重定向还可能把带鉴权头的请求送到第三方；HTTPS→HTTP 降级会丢 TLS 保护。
//
// 本模块是纯逻辑裁决：给定"当前请求 URL 与一跳 Location"，决定是否允许跟随，并对整条
// 重定向链做跳数 / 主机变化 / 协议降级 / 内网目标 / 凭据泄露的策略控制。不使用正则。

const (
	SRDReasonTooManyRedirects  = "srd-redirect-chain-too-long"
	SRDReasonDowngradeHTTPS    = "srd-https-to-http-downgrade"
	SRDReasonDangerousScheme   = "srd-redirect-dangerous-scheme"
	SRDReasonTargetPrivate     = "srd-redirect-target-private"
	SRDReasonCrossHostWithAuth = "srd-cross-host-redirect-carries-auth"
	SRDReasonUserInfoLeak      = "srd-redirect-url-userinfo"
	SRDReasonOpenRedirectHost  = "srd-redirect-host-not-allowlisted"
	SRDReasonBadLocation       = "srd-redirect-location-malformed"
)

// SRDPolicy 控制重定向跟随严格度。
type SRDPolicy struct {
	MaxHops               int
	ForbidDowngrade       bool
	AllowedSchemes        []string
	ForbidPrivateTarget   bool
	DropAuthCrossHost     bool
	AllowlistedHosts      []string // 空表示允许任意公网主机（仍受内网/降级约束）
	RestrictToAllowlist   bool
}

// SRDFinding 记录一跳重定向风险。
type SRDFinding struct {
	Reason string
	From   string
	To     string
	Detail string
}

// SRDRequest 描述当前这一跳的状态。
type SRDRequest struct {
	CurrentURL  string
	Location    string
	Hop         int
	CarriesAuth bool // 当前请求是否带 Authorization / Cookie
}

// DefaultSRDPolicy 返回默认严格策略。
func DefaultSRDPolicy() SRDPolicy {
	return SRDPolicy{
		MaxHops:             5,
		ForbidDowngrade:     true,
		AllowedSchemes:      []string{"http", "https"},
		ForbidPrivateTarget: true,
		DropAuthCrossHost:   true,
		RestrictToAllowlist: false,
	}
}

// srdSchemeHost 从 URL 纯字符拆出 scheme 与 host（含端口），失败返回 ok=false。
func srdSchemeHost(raw string) (scheme, host string, ok bool) {
	colon := -1
	for i := 0; i < len(raw); i++ {
		if raw[i] == ':' {
			colon = i
			break
		}
		if raw[i] == '/' || raw[i] == '?' || raw[i] == '#' {
			return "", "", false
		}
	}
	if colon < 0 {
		return "", "", false
	}
	scheme = srdLower(raw[:colon])
	rest := raw[colon+1:]
	if len(rest) < 2 || rest[0] != '/' || rest[1] != '/' {
		// 无 authority（如 file:/path 已在 scheme 面拦，http:opq 不合法）。
		return scheme, "", false
	}
	auth := rest[2:]
	end := len(auth)
	for i := 0; i < len(auth); i++ {
		if auth[i] == '/' || auth[i] == '?' || auth[i] == '#' {
			end = i
			break
		}
	}
	return scheme, auth[:end], true
}

// srdHostOnly 去掉 userinfo@ 与端口，返回纯主机（IPv6 去方括号）。
func srdHostOnly(authority string) (host string, hadUserInfo bool) {
	a := authority
	if at := srdLastByte(a, '@'); at >= 0 {
		hadUserInfo = true
		a = a[at+1:]
	}
	if len(a) >= 2 && a[0] == '[' {
		if cb := srdLastByte(a, ']'); cb > 0 {
			return a[1:cb], hadUserInfo
		}
	}
	if colon := srdLastByte(a, ':'); colon >= 0 {
		port := a[colon+1:]
		allDigit := len(port) > 0
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				allDigit = false
				break
			}
		}
		if allDigit {
			a = a[:colon]
		}
	}
	return a, hadUserInfo
}

func srdLastByte(s string, b byte) int {
	idx := -1
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			idx = i
		}
	}
	return idx
}

func srdLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func srdSchemeAllowed(s string, allowed []string) bool {
	for _, a := range allowed {
		if s == a {
			return true
		}
	}
	return false
}

func srdHostInList(host string, list []string) bool {
	h := srdLower(host)
	for _, x := range list {
		if srdLower(x) == h {
			return true
		}
	}
	return false
}

// SRDEvaluateHop 校验一跳重定向是否可跟随。
func SRDEvaluateHop(req SRDRequest, pol SRDPolicy) []SRDFinding {
	var out []SRDFinding
	add := func(reason, detail string) {
		out = append(out, SRDFinding{Reason: reason, From: req.CurrentURL, To: req.Location, Detail: detail})
	}
	if req.Hop > pol.MaxHops {
		add(SRDReasonTooManyRedirects, "")
	}
	toScheme, toAuth, ok := srdSchemeHost(req.Location)
	if !ok {
		add(SRDReasonBadLocation, "")
		return out
	}
	if !srdSchemeAllowed(toScheme, pol.AllowedSchemes) {
		add(SRDReasonDangerousScheme, toScheme)
	}
	fromScheme, _, _ := srdSchemeHost(req.CurrentURL)
	if pol.ForbidDowngrade && fromScheme == "https" && toScheme == "http" {
		add(SRDReasonDowngradeHTTPS, "")
	}
	toHost, hadUserInfo := srdHostOnly(toAuth)
	if hadUserInfo {
		add(SRDReasonUserInfoLeak, "")
	}
	if pol.ForbidPrivateTarget {
		if cls, ok := drgClassifyIP(toHost); ok && cls != DRGClassPublic {
			add(SRDReasonTargetPrivate, toHost)
		} else if srdLower(toHost) == "localhost" {
			add(SRDReasonTargetPrivate, "localhost")
		}
	}
	// 跨主机带鉴权。
	_, fromAuth, _ := srdSchemeHost(req.CurrentURL)
	fromHost, _ := srdHostOnly(fromAuth)
	crossHost := srdLower(fromHost) != srdLower(toHost)
	if crossHost && req.CarriesAuth && pol.DropAuthCrossHost {
		add(SRDReasonCrossHostWithAuth, toHost)
	}
	if pol.RestrictToAllowlist && !srdHostInList(toHost, pol.AllowlistedHosts) {
		add(SRDReasonOpenRedirectHost, toHost)
	}
	return out
}

// SRDEvaluateChain 对整条链逐跳校验（hops 为第 1..N 跳的 Location 序列）。
func SRDEvaluateChain(startURL string, locations []string, carriesAuth bool, pol SRDPolicy) []SRDFinding {
	var out []SRDFinding
	cur := startURL
	for i, loc := range locations {
		req := SRDRequest{CurrentURL: cur, Location: loc, Hop: i + 1, CarriesAuth: carriesAuth}
		f := SRDEvaluateHop(req, pol)
		out = append(out, f...)
		cur = loc
		// 一旦出现降级 / 危险协议 / 内网目标，后续不应再携带鉴权。
		if len(f) > 0 {
			carriesAuth = false
		}
	}
	return out
}

// SRDIsSafe 便捷判定单跳。
func SRDIsSafe(current, location string, carriesAuth bool) bool {
	return len(SRDEvaluateHop(SRDRequest{CurrentURL: current, Location: location, Hop: 1, CarriesAuth: carriesAuth},
		DefaultSRDPolicy())) == 0
}
