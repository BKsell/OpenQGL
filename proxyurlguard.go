package main

// proxyurlguard.go —— 出向 HTTP(S) 代理配置的凭据泄漏与绕过守卫。
//
// 背景：
//   启动器可能读取系统/用户配置的代理。代理 URL 是敏感配置，处理不当会泄漏凭据或被用来绕过
//   SSRF/钉扎策略：
//     - http://user:pass@proxy 中代理凭据会出现在日志/错误信息/CONNECT 行；
//     - 对 localhost/内网地址仍走外部代理，把内部主机名/令牌经第三方代理带出；
//     - NO_PROXY 配置过宽（如 "*"、后缀匹配 .com 命中所有站）导致本该走审计代理/抓包的流量直连；
//       反过来 NO_PROXY 缺失导致环回/元数据地址 169.254.169.254 被送到外部代理；
//     - 代理本身是明文 http，承载 CONNECT 隧道时只能保证到代理的保密性，凭据明文经过代理网络；
//     - socks 与 http 代理混用、自动配置 PAC 指向 http/任意外部 URL。
//   ssrfredirect/dnsrebinding 管目标主机，本模块专管"代理通道"本身的凭据与绕过面，纯字符串判定。

import "strings"

const (
	PRXReasonCredentialsInURL = "proxy-credentials-embedded-in-url"
	PRXReasonPlainHTTPProxy   = "proxy-cleartext-http-with-credentials"
	PRXReasonInternalViaProxy = "proxy-internal-or-loopback-target-sent-upstream"
	PRXReasonNoProxyTooBroad  = "proxy-no-proxy-rule-too-broad"
	PRXReasonMetadataViaProxy = "proxy-cloud-metadata-address-not-bypassed"
	PRXReasonPacOverCleartext = "proxy-pac-url-over-cleartext"
	PRXReasonNonHTTPScheme    = "proxy-unsupported-scheme"
)

// PRXView 描述代理配置。
type PRXView struct {
	ProxyURL       string
	HasCredentials bool
	PACURL         string
	NoProxyRules   []string
}

// PRXTarget 描述即将通过代理访问的目标。
type PRXTarget struct {
	Host       string
	IsLoopback bool
	IsPrivate  bool
	IsMetadata bool
}

// PRXFinding 记录一处代理风险。
type PRXFinding struct {
	Reason string
	Detail string
}

func prxLowerHost(raw string) (scheme, host string) {
	s := strings.TrimSpace(raw)
	rest := s
	if i := strings.Index(rest, "://"); i >= 0 {
		scheme = strings.ToLower(rest[:i])
		rest = rest[i+3:]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		if strings.IndexByte(rest[:at], '/') < 0 {
			rest = rest[at+1:]
		}
	}
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	return scheme, strings.ToLower(rest)
}

// PRXValidateConfig 校验代理 URL / PAC / NO_PROXY 配置本身。
func PRXValidateConfig(v PRXView) (safe bool, findings []PRXFinding) {
	scheme, _ := prxLowerHost(v.ProxyURL)
	if v.HasCredentials || strings.Contains(v.ProxyURL, "@") {
		findings = append(findings, PRXFinding{Reason: PRXReasonCredentialsInURL})
	}
	if scheme != "" && scheme != "http" && scheme != "https" &&
		scheme != "socks4" && scheme != "socks5" && scheme != "socks" {
		findings = append(findings, PRXFinding{Reason: PRXReasonNonHTTPScheme, Detail: scheme})
	}
	if scheme == "http" && (v.HasCredentials || strings.Contains(v.ProxyURL, "@")) {
		findings = append(findings, PRXFinding{Reason: PRXReasonPlainHTTPProxy})
	}

	pacScheme, _ := prxLowerHost(v.PACURL)
	if v.PACURL != "" && pacScheme == "http" {
		findings = append(findings, PRXFinding{Reason: PRXReasonPacOverCleartext})
	}

	for _, rule := range v.NoProxyRules {
		r := strings.ToLower(strings.TrimSpace(rule))
		if r == "*" || r == "all" || r == "0.0.0.0/0" || r == "::/0" {
			findings = append(findings, PRXFinding{Reason: PRXReasonNoProxyTooBroad, Detail: r})
		}
		if r == ".com" || r == ".net" || r == ".org" || r == ".cn" {
			findings = append(findings, PRXFinding{Reason: PRXReasonNoProxyTooBroad, Detail: r})
		}
	}
	return len(findings) == 0, findings
}

// prxRuleMatches 判断 NO_PROXY 规则是否命中目标主机（字面/后缀匹配）。
func prxRuleMatches(rule, host string) bool {
	r := strings.ToLower(strings.TrimSpace(rule))
	h := strings.ToLower(strings.TrimSpace(host))
	if r == "" {
		return false
	}
	if r == h {
		return true
	}
	if strings.HasPrefix(r, ".") && strings.HasSuffix(h, r) {
		return true
	}
	if !strings.HasPrefix(r, ".") && strings.HasSuffix(h, "."+r) {
		return true
	}
	return false
}

// PRXValidateRouting 判断某目标走代理是否安全（内网/环回/元数据不应出上游代理）。
func PRXValidateRouting(target PRXTarget, noProxyRules []string) (safe bool, findings []PRXFinding) {
	bypassed := false
	for _, r := range noProxyRules {
		if prxRuleMatches(r, target.Host) {
			bypassed = true
			break
		}
	}
	if target.IsLoopback || target.IsPrivate {
		if !bypassed {
			findings = append(findings, PRXFinding{Reason: PRXReasonInternalViaProxy,
				Detail: target.Host})
		}
	}
	if target.IsMetadata {
		if !bypassed {
			findings = append(findings, PRXFinding{Reason: PRXReasonMetadataViaProxy,
				Detail: target.Host})
		}
	}
	return len(findings) == 0, findings
}
