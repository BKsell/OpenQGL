package main

// timingcompareguard.go —— 机密值比较的常量时间原语与比较策略守卫。
//
// 背景：
//   启动器要比对令牌、HMAC 签名、state、PKCE verifier 等机密。直接用 ==/bytes.Equal 会在首个不匹配
//   字节提前返回，攻击者可测量响应耗时逐字节猜出正确值（timing side-channel）。本模块：
//     - 提供常量时间比较 TimingSafeEqual（对全部字节做累积异或，长度不同也先做标记再返回）；
//     - 提供字符串版本 TimingSafeEqualString；
//     - 提供比较策略审计：机密比较必须走常量时间路径，普通非机密等值可直接比较。
//   纯运算，无外部依赖，不使用正则。

// TimingSafeEqual 在常量时间内比较两个字节切片（相对长度）。
// 长度不同时仍遍历较短者累积差异，再以差一标记返回 false，避免长度本身以外的早退。
func TimingSafeEqual(a, b []byte) bool {
	la, lb := len(a), len(b)
	n := la
	if lb < n {
		n = lb
	}
	var diff byte
	if la != lb {
		diff = 1
	}
	for i := 0; i < n; i++ {
		diff |= a[i] ^ b[i]
	}
	// 长度更长的一方多出的字节也要计入，防止用截断串碰撞
	longer := a
	if lb > la {
		longer = b
	}
	for i := n; i < len(longer); i++ {
		diff |= longer[i]
	}
	return diff == 0
}

// TimingSafeEqualString 是字符串版常量时间比较。
func TimingSafeEqualString(a, b string) bool {
	return TimingSafeEqual([]byte(a), []byte(b))
}

// TCSecretKind 表示被比较值是否为机密。
const (
	TCKindPublic = 0 // 版本号、状态码等非机密，允许早退比较
	TCKindSecret = 1 // token/HMAC/state 等，必须常量时间
)

// TCFinding 表示一次比较方式选择问题。
type TCFinding struct {
	Reason string
}

// TCReasonNonConstantTimeSecret 表示对机密使用了早退比较。
const TCReasonNonConstantTimeSecret = "timing-secret-compared-with-early-exit-operator"

// TCAuditCompare 审计比较方式。
// usedConstantTime 由调用方如实报告实际采用的比较函数；secretKind 标记机密等级。
func TCAuditCompare(usedConstantTime bool, secretKind int) (safe bool, findings []TCFinding) {
	if secretKind == TCKindSecret && !usedConstantTime {
		findings = append(findings, TCFinding{Reason: TCReasonNonConstantTimeSecret})
	}
	return len(findings) == 0, findings
}

// TCHas 判定结果含某类问题。
func TCHas(findings []TCFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
