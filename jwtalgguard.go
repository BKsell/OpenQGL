package main

// jwtalgguard.go —— JWT/JWS 签名算法与密钥混淆守卫。
//
// 背景：
//   启动器若消费任何 JWT（自建登录、第三方验证服务、未来的 OIDC id_token），算法字段（alg）来自
//   令牌本身且不受保护，常见攻击：
//     - alg: "none"：无签名令牌被直接接受；
//     - 算法替换（RS256→HS256）：把公钥当 HMAC 密钥，用已知公钥伪造令牌；
//     - 接受弱/非对称空 alg、大小写混淆（"NoNe"）、kid 路径穿越（kid 选择密钥文件）；
//     - 对 HMAC 使用过短密钥。
//   本模块只审计"令牌头部声明的 alg + 验证方期望的算法族 + 密钥"，不做真实加密，不用正则。

const (
	JAReasonAlgNone      = "jwt-alg-none-unaccepted"
	JAReasonAlgMismatch  = "jwt-algorithm-family-mismatch-with-verifier"
	JAReasonAlgUnknown   = "jwt-algorithm-not-allowlisted"
	JAReasonWeakHMACKey  = "jwt-hmac-key-below-minimum-length"
	JAReasonKidTraversal = "jwt-kid-header-path-traversal"
	JAReasonEmptyToken   = "jwt-token-empty-or-malformed-segments"
)

// JAMinHMACKeyLen HMAC 密钥最小长度（字节）。
const JAMinHMACKeyLen = 32

// JAExpectKind 验证方期望的算法族。
type JAExpectKind int

const (
	JAKindHMAC JAExpectKind = iota
	JAKindRSA
	JAKindECDSA
)

// JAHeader 是已被（不做签名验证地）解析出的关键头部字段。
type JAHeader struct {
	Alg string
	Kid string
}

// JAFinding 记录一处 JWT 算法风险。
type JAFinding struct {
	Reason string
	Detail string
}

// JAAudit 审计令牌头部是否可按验证方策略进入签名验证。
func JAAudit(h JAHeader, expect JAExpectKind, hmacKeyLen int) (safe bool, findings []JAFinding) {
	alg := jaLower(h.Alg)
	if h.Alg == "" {
		findings = append(findings, JAFinding{Reason: JAReasonAlgUnknown})
	}
	switch alg {
	case "none", "":
		findings = append(findings, JAFinding{Reason: JAReasonAlgNone})
	case "hs256", "hs384", "hs512":
		if expect != JAKindHMAC {
			findings = append(findings, JAFinding{Reason: JAReasonAlgMismatch, Detail: alg})
		}
		if hmacKeyLen < JAMinHMACKeyLen {
			findings = append(findings, JAFinding{Reason: JAReasonWeakHMACKey,
				Detail: jaItoa(hmacKeyLen)})
		}
	case "rs256", "rs384", "rs512", "ps256", "ps384", "ps512":
		if expect != JAKindRSA {
			findings = append(findings, JAFinding{Reason: JAReasonAlgMismatch, Detail: alg})
		}
	case "es256", "es384", "es512":
		if expect != JAKindECDSA {
			findings = append(findings, JAFinding{Reason: JAReasonAlgMismatch, Detail: alg})
		}
	default:
		findings = append(findings, JAFinding{Reason: JAReasonAlgUnknown, Detail: h.Alg})
	}

	if jaHasTraversal(h.Kid) {
		findings = append(findings, JAFinding{Reason: JAReasonKidTraversal, Detail: h.Kid})
	}
	return len(findings) == 0, findings
}

// JACheckSegments 粗校 JWT 必须有三段（header.payload.signature），且签名段非空。
func JACheckSegments(token string) (safe bool, findings []JAFinding) {
	if token == "" {
		return false, []JAFinding{{Reason: JAReasonEmptyToken}}
	}
	dots := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			dots++
		}
	}
	if dots != 2 {
		return false, []JAFinding{{Reason: JAReasonEmptyToken, Detail: "segments!=3"}}
	}
	// 末段（签名）不能为空
	last := token
	for i := len(last) - 1; i >= 0; i-- {
		if last[i] == '.' {
			last = last[i+1:]
			break
		}
	}
	if last == "" {
		return false, []JAFinding{{Reason: JAReasonAlgNone, Detail: "empty-signature"}}
	}
	return true, nil
}

func jaHasTraversal(kid string) bool {
	if kid == "" {
		return false
	}
	if jaContains(kid, "..") {
		return true
	}
	if jaContains(kid, "/") || jaContains(kid, `\`) {
		return true
	}
	if jaContains(kid, ":") {
		return true
	}
	return false
}

func jaContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func jaLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func jaItoa(i int) string {
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

// JAHasReason 判定结果含某类问题。
func JAHasReason(findings []JAFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
