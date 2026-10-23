package main

// wildcardcorsguard.go —— 出向/本地服务 CORS 响应策略守卫（反射型与通配型）。
//
// 背景：
//   启动器可能内置本地 HTTP 服务（回调接收、本地调试），也会消费带 CORS 头的接口。危险配置：
//     - Access-Control-Allow-Origin 反射任意 Origin，同时 Allow-Credentials: true——任意站点可带凭据跨域读；
//     - ACAO: "*" 与 credentials 并存（规范禁止，但部分实现/旧浏览器仍放行）；
//     - 允许 "null" origin（沙箱 iframe/file 文档可伪造 null）；
//     - 仅靠后缀匹配 allowlist（evil-example.com 匹配 example.com 子串）导致放行；
//     - AC-Allow-Headers/P-Methods 用通配且可凭据，放大可调用面。
//   纯字符串/精确主机匹配判定，不使用正则。

const (
	WCReasonWildcardWithCredentials = "cors-wildcard-origin-with-credentials"
	WCReasonReflectsAnyOrigin       = "cors-reflects-arbitrary-origin-with-credentials"
	WCReasonNullOrigin              = "cors-allows-null-origin"
	WCReasonSuffixMatchBypass       = "cors-origin-allowlist-suffix-substring-match"
	WCReasonWildcardHeadersCreds    = "cors-wildcard-allowed-headers-with-credentials"
)

// WCFinding 记录一处 CORS 风险。
type WCFinding struct {
	Reason string
	Detail string
}

// WCResponse 描述一个 CORS 响应/策略。
type WCResponse struct {
	AllowOrigin      string
	AllowCredentials bool
	AllowHeaders     string // Access-Control-Allow-Headers
	RequestOrigin    string // 触发响应的请求 Origin
}

// WCAudit 审计响应；allowedOrigins 为精确允许来源（小写）。
func WCAudit(resp WCResponse, allowedOrigins map[string]bool) (safe bool, findings []WCFinding) {
	ao := resp.AllowOrigin

	if ao == "*" && resp.AllowCredentials {
		findings = append(findings, WCFinding{Reason: WCReasonWildcardWithCredentials})
	}
	if ao == "null" {
		findings = append(findings, WCFinding{Reason: WCReasonNullOrigin})
	}

	// 反射型：响应把请求 Origin 原样回显，且带凭据，又不在精确白名单内
	if resp.RequestOrigin != "" && ao == resp.RequestOrigin && resp.AllowCredentials {
		if !allowedOrigins[wcLower(ao)] {
			findings = append(findings, WCFinding{Reason: WCReasonReflectsAnyOrigin,
				Detail: ao})
		}
	}

	// 通配响应头 + 凭据
	if wcHasWildcardToken(resp.AllowHeaders) && resp.AllowCredentials {
		findings = append(findings, WCFinding{Reason: WCReasonWildcardHeadersCreds})
	}

	return len(findings) == 0, findings
}

// WCAllowedByExactSuffix 判断 origin 是否被精确白名单或"点子域"规则放行。
// rule 为 "example.com" 时仅放行 https://example.com 与 https://*.example.com，
// 不允许 evil-example.com 这类纯后缀子串。
func WCAllowedByExactSuffix(origin, scheme, rule string) bool {
	host := origin
	if wcHasPrefix(host, scheme+"://") {
		host = host[len(scheme+"://"):]
	}
	// 去掉端口
	if i := wcIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = wcLower(host)
	rule = wcLower(rule)
	if host == rule {
		return true
	}
	return wcHasSuffix(host, "."+rule)
}

// WCAuditSuffixRule 检查后缀规则是否过宽/含通配，容易被子串或任意域绕过。
func WCAuditSuffixRule(rule string) (vulnerable bool) {
	r := wcLower(wcTrim(rule))
	switch r {
	case "", "*", "com", "cn", "com.cn", "net", "org", "io":
		return true
	}
	for i := 0; i < len(r); i++ {
		if r[i] == '*' {
			return true
		}
	}
	return false
}

func wcHasWildcardToken(s string) bool {
	for _, tok := range wcSplitComma(s) {
		if wcTrim(tok) == "*" {
			return true
		}
	}
	return false
}

func wcSplitComma(s string) []string {
	var out []string
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

func wcTrim(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func wcLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func wcHasPrefix(s, pre string) bool {
	return len(s) >= len(pre) && s[:len(pre)] == pre
}

func wcHasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

func wcIndexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// WCHasReason 判定结果含某类问题。
func WCHasReason(findings []WCFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
