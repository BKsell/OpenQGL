package main

// certpinguard.go —— SPKI 证书公钥钉扎集合校验（区别于 trustcallback 的链/有效期校验）。
//
// 背景：
//   trustcallbackguard 管"是否正确校验证书链/有效期/SAN"。本模块管另一条独立防线：公钥钉扎
//   （HPKP 已被浏览器废弃，但客户端对固定高价值端点——Mojang/微软登录、自有更新源——仍可做
//   TOFU/预置 pin 校验）。钉扎本身若实现错误反而更危险：
//     - 只钉单个 pin、无备份 pin：密钥轮换即永久 DoS，或被迫整体放行；
//     - 把"主机名/证书序列号"当 pin（不随密钥绑定）；
//     - pin 用 SHA1（碰撞风险）或自造哈希；base64 错（标准 base64 vs url-safe、缺填充）；
//     - 永不过期的 pin 集，被入侵后无法撤销；pin 集为空却 fail-open；
//     - 通配/过宽主机覆盖（一个 pin 覆盖全部域名）。
//   本模块只做 pin 集合结构与匹配判定（pin 摘要由调用方算好喂入，外部校验哈希算法保持原样），
//   纯字符串/字节判定，不使用正则。

const (
	SPNPReasonEmptyPinSet       = "pinning-empty-pin-set-fail-open-risk"
	SPNPReasonNoBackupPin       = "pinning-single-pin-without-backup"
	SPNPReasonWeakPinAlgorithm  = "pinning-weak-hash-algorithm"
	SPNPReasonMalformedPin      = "pinning-malformed-base64-pin"
	SPNPReasonNoHostMatch       = "pinning-no-pinned-key-for-host"
	SPNPReasonHostCoverageBroad = "pinning-host-pattern-too-broad"
	SPNPReasonPinSetExpired     = "pinning-pin-set-expired"
	SPNPReasonPinSetNotYetValid = "pinning-pin-set-not-yet-valid"
)

// SPNPPin 是一条钉扎项。
type SPNPPin struct {
	Algorithm string // 仅接受 sha256
	DigestB64 string // 标准 base64（带填充）
}

// SPNPHostRule 是某主机的钉扎规则。
type SPNPHostRule struct {
	Host       string
	Pins       []SPNPPin
	NotBefore  int64 // unix 秒，0 表示不限
	NotAfter   int64 // unix 秒，0 表示不限
	IncludeSub bool  // 是否覆盖子域（仅允许精确的一级受控父域）
}

// SPNPFinding 记录一处钉扎风险。
type SPNPFinding struct {
	Reason string
	Host   string
}

// SPNPResult 校验结论。
type SPNPResult struct {
	Safe     bool
	Findings []SPNPFinding
}

// SPNPValidateRules 校验钉扎规则集本身的结构安全。now 为 unix 秒。
func SPNPValidateRules(rules []SPNPHostRule, now int64) SPNPResult {
	var findings []SPNPFinding
	for _, r := range rules {
		if len(r.Pins) == 0 {
			findings = append(findings, SPNPFinding{Reason: SPNPReasonEmptyPinSet, Host: r.Host})
		}
		if len(r.Pins) == 1 {
			findings = append(findings, SPNPFinding{Reason: SPNPReasonNoBackupPin, Host: r.Host})
		}
		for _, p := range r.Pins {
			if p.Algorithm != "sha256" {
				findings = append(findings, SPNPFinding{Reason: SPNPReasonWeakPinAlgorithm, Host: r.Host})
			}
			if !spnpIsValidStandardBase64(p.DigestB64) || !spnpIsSHA256Length(p.DigestB64) {
				findings = append(findings, SPNPFinding{Reason: SPNPReasonMalformedPin, Host: r.Host})
			}
		}
		if r.NotBefore > 0 && now < r.NotBefore {
			findings = append(findings, SPNPFinding{Reason: SPNPReasonPinSetNotYetValid, Host: r.Host})
		}
		if r.NotAfter > 0 && now > r.NotAfter {
			findings = append(findings, SPNPFinding{Reason: SPNPReasonPinSetExpired, Host: r.Host})
		}
		if r.IncludeSub && spnpHostTooBroad(r.Host) {
			findings = append(findings, SPNPFinding{Reason: SPNPReasonHostCoverageBroad, Host: r.Host})
		}
	}
	return SPNPResult{Safe: len(findings) == 0, Findings: findings}
}

// SPNPMatch 在握手后用对端证书的 SPKI 摘要（调用方已按 sha256 计算并标准 base64）匹配 pin。
// 匹配到任一 pin 即通过；规则缺失时按 failClosed=true 拒绝、false 放行（调用方显式选择）。
func SPNPMatch(rules []SPNPHostRule, host, spkiB64 string, failClosed bool) SPNPResult {
	for _, r := range rules {
		if !spnpHostCovers(r, host) {
			continue
		}
		for _, p := range r.Pins {
			if p.Algorithm == "sha256" && p.DigestB64 == spkiB64 {
				return SPNPResult{Safe: true}
			}
		}
		return SPNPResult{Safe: false, Findings: []SPNPFinding{
			{Reason: SPNPReasonNoHostMatch, Host: host}}}
	}
	return SPNPResult{Safe: !failClosed, Findings: []SPNPFinding{
		{Reason: SPNPReasonNoHostMatch, Host: host}}}
}

func (r SPNPResult) HasReason(reason string) bool {
	for _, f := range r.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func spnpHostCovers(rule SPNPHostRule, host string) bool {
	if rule.Host == host {
		return true
	}
	if rule.IncludeSub && spnpHasSuffix(host, "."+rule.Host) {
		return true
	}
	return false
}

// spnpHostTooBroad 判定 IncludeSub 的父域是否过宽（公共后缀级，如 com/net/org）。
func spnpHostTooBroad(host string) bool {
	dots := 0
	for i := 0; i < len(host); i++ {
		if host[i] == '.' {
			dots++
		}
	}
	if dots == 0 {
		return true
	}
	idx := spnpLastDot(host)
	last := host
	if idx >= 0 {
		last = host[idx+1:]
	}
	for _, pub := range []string{"com", "net", "org", "io", "cn", "co", "dev", "app"} {
		if last == pub && dots == 1 {
			return true
		}
	}
	return false
}

func spnpLastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

func spnpHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// spnpIsValidStandardBase64 校验标准 base64 字符集与长度为 4 的倍数（带填充）。
func spnpIsValidStandardBase64(s string) bool {
	if len(s) == 0 || len(s)%4 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlpha := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		isDigit := c >= '0' && c <= '9'
		isSym := c == '+' || c == '/' || c == '='
		if !isAlpha && !isDigit && !isSym {
			return false
		}
		if c == '=' && i < len(s)-2 {
			return false
		}
	}
	return true
}

// spnpIsSHA256Length 标准 base64 编码 32 字节摘要为 44 字符（含一个 '='）。
func spnpIsSHA256Length(b64 string) bool {
	return len(b64) == 44
}
