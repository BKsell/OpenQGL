package main

// trustcallbackguard.go —— 自定义 TLS 证书校验回调（VerifyConnection/VerifyPeerCertificate）守卫。
//
// 背景：
//   Go 允许用 tls.Config 的 InsecureSkipVerify + 自定义 VerifyConnection/VerifyPeerCertificate 自己
//   实现证书校验（如证书钉扎）。这把"信任决定"交给应用代码，极易写错成"形式上自定义、实际全放行"：
//     - 回调无条件 return nil（任何证书都通过，等同 InsecureSkipVerify）；
//     - 回调里把 err != nil 直接忽略/吞掉，只打印不拒绝；
//     - 设置了自定义回调却仍把 InsecureSkipVerify=true，且回调不覆盖主机名/链/有效期全部维度；
//     - 校验只比证书存在（len(certs)>0）不验签名/颁发者/过期；
//     - 钉扎只比公钥前缀/可空指针，空钉扎集 = 全匹配；
//     - 不做时间校验（NotBefore/NotAfter），接受过期/未生效证书；
//     - 主机名校验被关闭（ServerName 为空且回调不验 DNS/IP SAN）。
//   tlsdowngradeguard 管配置版本/cipher，truststoreguard 管信任库来源，本模块专管"自定义回调本身
//   是否真的在拒绝"，依据调用方登记的回调行为视图判定，纯布尔/数值，不使用正则。

const (
	TCBReasonCallbackAlwaysNil   = "tls-callback-always-returns-nil"
	TCBReasonErrorSwallowed      = "tls-callback-ignores-verification-error"
	TCBReasonOnlyChecksPresence  = "tls-callback-only-checks-certificate-presence"
	TCBReasonNoChainVerification = "tls-callback-skips-chain-signature"
	TCBReasonNoExpiryCheck       = "tls-callback-skips-validity-period"
	TCBReasonEmptyPinSet         = "tls-callback-pin-set-empty-matches-all"
	TCBReasonPinPrefixOnly       = "tls-callback-pin-compares-prefix-only"
	TCBReasonNilablePinPointer   = "tls-callback-pin-nilable-deref-allows-bypass"
	TCBReasonNoHostnameCheck     = "tls-callback-skips-hostname-san"
	TCBReasonInsecureAndWeakCB   = "tls-insecure-skip-verify-with-incomplete-callback"
)

// TCBView 描述自定义校验回调的实际行为。
type TCBView struct {
	Host                   string
	InsecureSkipVerifySet  bool
	AlwaysReturnsNil       bool // 回调体恒定返回 nil
	IgnoresIncomingErr     bool // 入参 err 被丢弃
	OnlyChecksPresence     bool // 仅判断证书非空
	VerifiesChainSignature bool
	ChecksNotBeforeAfter   bool
	ChecksHostnameSAN      bool
	PinSetEmpty            bool
	PinPrefixOnly          bool
	PinNilableDeref        bool
}

// TCBFinding 记录一处回调风险。
type TCBFinding struct {
	Reason string
	Host   string
	Detail string
}

// TCBEvaluate 审计回调行为。一个"真正在拒绝"的自定义回调必须覆盖链、有效期、主机名（或钉扎）。
func TCBEvaluate(v TCBView) (safe bool, findings []TCBFinding) {
	add := func(reason, detail string) {
		findings = append(findings, TCBFinding{Reason: reason, Host: v.Host, Detail: detail})
	}

	if v.AlwaysReturnsNil {
		add(TCBReasonCallbackAlwaysNil, "return-nil")
	}
	if v.IgnoresIncomingErr {
		add(TCBReasonErrorSwallowed, "err-ignored")
	}
	if v.OnlyChecksPresence {
		add(TCBReasonOnlyChecksPresence, "len>0")
	}
	if !v.VerifiesChainSignature {
		add(TCBReasonNoChainVerification, "no-chain")
	}
	if !v.ChecksNotBeforeAfter {
		add(TCBReasonNoExpiryCheck, "no-time")
	}
	if v.PinSetEmpty {
		add(TCBReasonEmptyPinSet, "empty-pins")
	}
	if v.PinPrefixOnly {
		add(TCBReasonPinPrefixOnly, "prefix")
	}
	if v.PinNilableDeref {
		add(TCBReasonNilablePinPointer, "nilable")
	}
	strongPin := !v.PinSetEmpty && !v.PinPrefixOnly && !v.PinNilableDeref
	// 主机名校验：没有可靠钉扎时必须显式校验主机名/SAN
	if !v.ChecksHostnameSAN && !strongPin {
		add(TCBReasonNoHostnameCheck, "no-san")
	}
	if v.InsecureSkipVerifySet {
		// 用 InsecureSkipVerify 承接自定义回调时，回调必须完整覆盖链+时间+主机名/钉扎
		complete := v.VerifiesChainSignature && v.ChecksNotBeforeAfter &&
			(v.ChecksHostnameSAN || strongPin)
		if !complete {
			add(TCBReasonInsecureAndWeakCB, "incomplete")
		}
	}
	return len(findings) == 0, findings
}

// TCBExpectError 是一个供回调统一使用的判定助手：err 非 nil 必须拒绝，不得吞错。
func TCBExpectError(verifyErr error, certsPresent bool) (reject bool, reason string) {
	if verifyErr != nil {
		return true, TCBReasonErrorSwallowed
	}
	if !certsPresent {
		return true, TCBReasonOnlyChecksPresence
	}
	return false, ""
}
