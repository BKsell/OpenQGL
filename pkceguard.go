package main

// pkceguard.go —— OAuth PKCE（RFC 7636）与 state 抗 CSRF 守卫。
//
// 背景：
//   桌面启动器走带公共客户端的授权码流程。没有 client_secret 时，PKCE 是阻止授权码注入
//   （code injection）的关键：本地先造高熵 code_verifier，再给授权服务器 code_challenge。
//   回调时必须用同一个 verifier 换 token。常见缺陷：
//     - verifier 太短 / 字符集不足 / 可预测（时间戳、自增、固定串）；
//     - 误用 plain challenge（method=plain），等于没保护；
//     - S256 的 challenge 不是正确的 base64url(SHA-256(verifier))（长度/字符集）；
//     - state 缺失或可预测，登录回调可被跨站伪造（登录 CSRF）；
//     - 回调拿到的 code 与 state 未绑定即直接兑换。
//   本模块做结构与强度校验（不在这里做 SHA-256，验签由调用方完成后用 VerifyS256 比对）。
//   纯字节实现，不使用正则。

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

const (
	PKCEReasonVerifierTooShort  = "pkce-verifier-too-short"
	PKCEReasonVerifierTooLong   = "pkce-verifier-too-long"
	PKCEReasonVerifierCharset   = "pkce-verifier-bad-charset"
	PKCEReasonPlainMethod       = "pkce-plain-challenge-method"
	PKCEReasonUnknownMethod     = "pkce-unknown-challenge-method"
	PKCEReasonChallengeBadLen   = "pkce-challenge-bad-length"
	PKCEReasonChallengeMismatch = "pkce-challenge-mismatch"
	PKCEReasonStateTooShort     = "pkce-state-too-short"
	PKCEReasonStatePredictable  = "pkce-state-predictable"
	PKCEReasonLowEntropy        = "pkce-low-entropy"
)

const (
	pkceVerifierMinLen = 43 // RFC7636：43..128
	pkceVerifierMaxLen = 128
	pkceStateMinLen    = 16
	s256B64Len         = 43 // base64url(sha256)=43，无填充
)

// PKCEPolicy 设定校验严格度。
type PKCEPolicy struct {
	RequireS256             bool
	StateMinEntropyDistinct int
	MinStateLen             int
}

// PKCEFinding 记录一处 PKCE/state 风险。
type PKCEFinding struct {
	Reason string
	Detail string
}

// DefaultPKCEPolicy 返回默认严格策略。
func DefaultPKCEPolicy() PKCEPolicy {
	return PKCEPolicy{RequireS256: true, StateMinEntropyDistinct: 16, MinStateLen: pkceStateMinLen}
}

// pkceVerifierChar 判断是否为 RFC7636 允许的 unreserved 字符。
func pkceVerifierChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '-', '.', '_', '~':
		return true
	}
	return false
}

func pkceDistinct(s string) int {
	seen := [256]bool{}
	n := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			n++
		}
	}
	return n
}

// PKCEValidateVerifier 校验 code_verifier 的长度与字符集及熵。
func PKCEValidateVerifier(verifier string, policy PKCEPolicy) (safe bool, findings []PKCEFinding) {
	if len(verifier) < pkceVerifierMinLen {
		findings = append(findings, PKCEFinding{Reason: PKCEReasonVerifierTooShort,
			Detail: itoaPKCE(int64(len(verifier)))})
	}
	if len(verifier) > pkceVerifierMaxLen {
		findings = append(findings, PKCEFinding{Reason: PKCEReasonVerifierTooLong})
	}
	for i := 0; i < len(verifier); i++ {
		if !pkceVerifierChar(verifier[i]) {
			findings = append(findings, PKCEFinding{Reason: PKCEReasonVerifierCharset,
				Detail: string(verifier[i])})
			break
		}
	}
	if pkceDistinct(verifier) < 16 {
		findings = append(findings, PKCEFinding{Reason: PKCEReasonLowEntropy,
			Detail: itoaPKCE(int64(pkceDistinct(verifier)))})
	}
	return len(findings) == 0, findings
}

// PKCES256Challenge 由 verifier 计算标准 S256 challenge（base64url 无填充）。
func PKCES256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func pkceBase64URLChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '-', '_':
		return true
	}
	return false
}

// PKCEValidateChallenge 校验客户端声明的 challenge 与方法；expected 为按 verifier 重算的值（可空）。
func PKCEValidateChallenge(method, challenge, expected string, policy PKCEPolicy) (safe bool, findings []PKCEFinding) {
	m := strings.ToLower(method)
	if m == "" || m == "plain" {
		findings = append(findings, PKCEFinding{Reason: PKCEReasonPlainMethod})
	} else if m != "s256" {
		findings = append(findings, PKCEFinding{Reason: PKCEReasonUnknownMethod, Detail: m})
	}
	if m == "s256" || policy.RequireS256 {
		if len(challenge) != s256B64Len {
			findings = append(findings, PKCEFinding{Reason: PKCEReasonChallengeBadLen,
				Detail: itoaPKCE(int64(len(challenge)))})
		}
		for i := 0; i < len(challenge); i++ {
			if !pkceBase64URLChar(challenge[i]) {
				findings = append(findings, PKCEFinding{Reason: PKCEReasonChallengeBadLen,
					Detail: "charset"})
				break
			}
		}
		if expected != "" && challenge != expected {
			findings = append(findings, PKCEFinding{Reason: PKCEReasonChallengeMismatch})
		}
	}
	return len(findings) == 0, findings
}

// pkcePredictable 粗判 state 是否由明显可预测材料构成。
func pkcePredictable(state string) bool {
	if len(state) == 0 {
		return true
	}
	// 全同一字符
	same := true
	for i := 1; i < len(state); i++ {
		if state[i] != state[0] {
			same = false
			break
		}
	}
	if same {
		return true
	}
	// 纯数字（可被枚举/猜测）
	allDigit := true
	for i := 0; i < len(state); i++ {
		if state[i] < '0' || state[i] > '9' {
			allDigit = false
			break
		}
	}
	return allDigit
}

// PKCEValidateState 校验登录回调 state 的强度。
func PKCEValidateState(state string, policy PKCEPolicy) (safe bool, findings []PKCEFinding) {
	minLen := policy.MinStateLen
	if minLen <= 0 {
		minLen = pkceStateMinLen
	}
	if len(state) < minLen {
		findings = append(findings, PKCEFinding{Reason: PKCEReasonStateTooShort,
			Detail: itoaPKCE(int64(len(state)))})
	}
	if pkcePredictable(state) {
		findings = append(findings, PKCEFinding{Reason: PKCEReasonStatePredictable})
	}
	if pkceDistinct(state) < policy.StateMinEntropyDistinct {
		findings = append(findings, PKCEFinding{Reason: PKCEReasonLowEntropy,
			Detail: itoaPKCE(int64(pkceDistinct(state)))})
	}
	return len(findings) == 0, findings
}

func itoaPKCE(i int64) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
