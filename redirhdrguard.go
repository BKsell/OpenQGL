package main

// redirhdrguard.go —— HTTP 跨主机重定向时敏感请求头/Cookie 泄漏守卫。
//
// 背景：
//   启动器的下载/元数据请求会跟随 3xx 重定向。Go net/http 默认会跟随到不同主机，但在跨主机
//   （甚至跨子域）时，是否继续携带 Authorization、Cookie、代理凭据、自定义令牌头，决定了令牌
//   会不会被一个"看似正常"的 302 送到攻击者域名：
//     - 下载站 302 到对象存储/CDN 是正常的，但若原请求带了 Bearer 令牌，跨信任域必须剥离；
//     - Cookie 的 Domain=.example.com 会被自动带到任何子域，重定向到被接管子域即泄漏；
//     - 从 https 降级到 http 时仍带 Cookie/Authorization（明文可截获）；
//     - 301/302/303 把 POST 改成 GET 但实现仍保留 body 中的敏感表单；
//     - 重定向次数无界（重定向环/放大），或跳转到非 http(s) scheme。
//   redirectltdguard 管的是"登录回跳地址白名单"，本模块管的是"通用 HTTP 客户端在跳转时如何处理
//   凭据与请求体"，纯字符串/主机比较，不使用正则。

import "strings"

const (
	RHGReasonAuthHeaderCrossHost  = "redirect-authorization-header-leaks-cross-host"
	RHGReasonCookieCrossHost      = "redirect-cookie-leaks-cross-host"
	RHGReasonCustomTokenCrossHost = "redirect-custom-token-header-leaks"
	RHGReasonCookieDomainWide     = "redirect-cookie-domain-scope-too-wide"
	RHGReasonDowngradeToHTTP      = "redirect-downgrade-https-to-http-with-credentials"
	RHGReasonBodyKeptOn303        = "redirect-sensitive-body-kept-after-303"
	RHGReasonTooManyRedirects     = "redirect-chain-too-long"
	RHGReasonRedirectLoop         = "redirect-loop-detected"
	RHGReasonNonHTTPSchemeTarget  = "redirect-non-http-scheme-target"
)

// RHGPolicy 控制重定向凭据处理。
type RHGPolicy struct {
	MaxRedirects              int
	StripAuthCrossHost        bool
	StripCookiesCrossHost     bool
	StripCustomTokenCrossHost bool
	ForbidSchemeDowngrade     bool
	AllowedSameRegistrable    bool // 是否允许在同一注册域的不同子域间保留凭据
}

// RHGHop 描述一次跳转。
type RHGHop struct {
	FromScheme string
	FromHost   string
	ToScheme   string
	ToHost     string
	StatusCode int
}

// RHGRequestState 描述当前请求携带的敏感数据。
type RHGRequestState struct {
	HasAuthorization   bool
	HasCookie          bool
	CustomTokenHeaders []string // 如 X-Api-Key
	HasSensitiveBody   bool
	CookieDomains      []string // Cookie 的 Domain 属性（小写）
}

// RHGFinding 记录一处重定向泄漏风险。
type RHGFinding struct {
	Reason string
	Detail string
}

// DefaultRHGPolicy 默认跨主机剥离凭据、禁止降级、最多 10 跳。
func DefaultRHGPolicy() RHGPolicy {
	return RHGPolicy{
		MaxRedirects:              10,
		StripAuthCrossHost:        true,
		StripCookiesCrossHost:     true,
		StripCustomTokenCrossHost: true,
		ForbidSchemeDowngrade:     true,
		AllowedSameRegistrable:    false,
	}
}

func rhgLHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		// 去掉端口，但保留 IPv6 粗判（回环由其它模块管）
		if !strings.HasPrefix(h, "[") {
			h = h[:i]
		}
	}
	return h
}

// rhgRegistrable 粗取注册域（最后两段），仅用于"同注册域子域"判定。
func rhgRegistrable(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return host
}

// rhgHostChanged 判断主机是否变化；sameReg=true 表示仅子域变化（同注册域）。
func rhgHostChanged(from, to string) (changed bool, sameReg bool) {
	f := rhgLHost(from)
	t := rhgLHost(to)
	if f == t {
		return false, false
	}
	return true, rhgRegistrable(f) == rhgRegistrable(t)
}

func rhgCookieDomainWide(domains []string, host string) bool {
	h := rhgLHost(host)
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, ".")
		if d == "" {
			continue
		}
		// Domain 覆盖范围大于当前主机所在域，即过宽
		if d != h && !strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// RHGEvaluateChain 评估整条重定向链上的凭据处理。
func RHGEvaluateChain(hops []RHGHop, state RHGRequestState, policy RHGPolicy) (safe bool, findings []RHGFinding) {
	if len(hops) > policy.MaxRedirects {
		findings = append(findings, RHGFinding{Reason: RHGReasonTooManyRedirects,
			Detail: itoaRHG(len(hops))})
	}

	visited := map[string]int{}
	for i, hop := range hops {
		fromKey := strings.ToLower(hop.FromScheme) + "://" + rhgLHost(hop.FromHost)
		visited[fromKey]++
		toKey := strings.ToLower(hop.ToScheme) + "://" + rhgLHost(hop.ToHost)
		visited[toKey]++

		ts := strings.ToLower(hop.ToScheme)
		if ts != "http" && ts != "https" {
			findings = append(findings, RHGFinding{Reason: RHGReasonNonHTTPSchemeTarget, Detail: ts})
		}

		changed, sameReg := rhgHostChanged(hop.FromHost, hop.ToHost)
		schemeDowngrade := strings.EqualFold(hop.FromScheme, "https") && ts == "http"
		crossTrust := changed && !(policy.AllowedSameRegistrable && sameReg)

		if schemeDowngrade {
			if policy.ForbidSchemeDowngrade && (state.HasAuthorization || state.HasCookie) {
				findings = append(findings, RHGFinding{Reason: RHGReasonDowngradeToHTTP,
					Detail: itoaRHG(i)})
			}
		}

		if crossTrust {
			if policy.StripAuthCrossHost && state.HasAuthorization {
				findings = append(findings, RHGFinding{Reason: RHGReasonAuthHeaderCrossHost,
					Detail: rhgLHost(hop.ToHost)})
			}
			if policy.StripCookiesCrossHost && state.HasCookie {
				findings = append(findings, RHGFinding{Reason: RHGReasonCookieCrossHost,
					Detail: rhgLHost(hop.ToHost)})
			}
			if policy.StripCustomTokenCrossHost && len(state.CustomTokenHeaders) > 0 {
				findings = append(findings, RHGFinding{Reason: RHGReasonCustomTokenCrossHost,
					Detail: strings.Join(state.CustomTokenHeaders, ",")})
			}
		}

		// 303 后敏感 body 不应继续发送
		if hop.StatusCode == 303 && state.HasSensitiveBody {
			findings = append(findings, RHGFinding{Reason: RHGReasonBodyKeptOn303, Detail: itoaRHG(i)})
		}
	}

	for key, count := range visited {
		if count > 2 {
			findings = append(findings, RHGFinding{Reason: RHGReasonRedirectLoop, Detail: key})
		}
	}
	if rhgCookieDomainWide(state.CookieDomains, rootHostRHG(hops)) {
		findings = append(findings, RHGFinding{Reason: RHGReasonCookieDomainWide})
	}
	return len(findings) == 0, findings
}

func rootHostRHG(hops []RHGHop) string {
	if len(hops) == 0 {
		return ""
	}
	return hops[0].FromHost
}

func itoaRHG(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
