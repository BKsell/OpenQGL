package main

// tlsdowngradeguard.go —— 出向连接 TLS 降级/旁路配置守卫（独立于既有 tlssecuritypolicy/tlsconnpin）。
//
// 背景：
//   启动器连接微软/Mojang/皮肤站/Modrinth 等 HTTPS 接口。除既有连接策略与证书固定模块外，
//   还需要在"建立 *tls.Config"这一刻拦截几类把整条传输安全清零的配置：
//     - InsecureSkipVerify 全局放开或被意外写死；
//     - MinVersion 落在 SSL3.0/TLS1.0/TLS1.1（POODLE/BEAST/降级）；
//     - CipherSuites 里混入 RC4/3DES/EXPORT/CBC-SHA1/NULL/anon 套件；
//     - 配置了自定义校验回调却在失败时不返回错误（形同虚设的 hook）；
//     - 允许自由 TLS 重协商（RenegotiationFreely）造成请求走私/会话注入面。
//   本模块对调用方映射进来的"逻辑配置视图"做判定，纯数值/字符串比较，不使用正则，也不替代
//   真实证书校验。

const (
	TLSDGReasonSkipVerify        = "tlsdg-skip-verify"
	TLSDGReasonBypassTooBroad    = "tlsdg-verify-bypass-too-broad"
	TLSDGReasonMinVersionLow     = "tlsdg-min-version-too-low"
	TLSDGReasonMinVersionUnset   = "tlsdg-min-version-unset"
	TLSDGReasonWeakCipher        = "tlsdg-weak-cipher-suite"
	TLSDGReasonNullAnonCipher    = "tlsdg-null-anon-cipher"
	TLSDGReasonHookNotEnforcing  = "tlsdg-verify-hook-not-enforcing"
	TLSDGReasonRenegotiationOpen = "tlsdg-renegotiation-freely-accepted"
	TLSDGReasonMaxBelowMin       = "tlsdg-max-version-below-min"
)

// 与 crypto/tls 对齐的版本号。
const (
	tlsdgSSL30 = 0x0300
	tlsdgTLS10 = 0x0301
	tlsdgTLS11 = 0x0302
	tlsdgTLS12 = 0x0303
	tlsdgTLS13 = 0x0304
)

// TLSDGView 是真实 tls.Config 安全字段的投影。
type TLSDGView struct {
	ServerName             string
	InsecureSkipVerify     bool
	MinVersion             uint16
	MaxVersion             uint16
	CipherSuites           []uint16
	HasPeerCertHook        bool
	PeerCertHookEnforces   bool
	HasConnectionHook      bool
	ConnectionHookEnforces bool
	RenegotiationFreely    bool
	BypassScopeHosts       []string
}

// TLSDGPolicy 设定最低要求。
type TLSDGPolicy struct {
	RequireExplicitMinVersion bool
	MinAllowedVersion         uint16
	ForbidWeakCiphers         bool
	AllowScopedSkipVerify     bool
}

// TLSDGFinding 记录一处风险。
type TLSDGFinding struct {
	Reason string
	Detail string
}

// DefaultTLSDGPolicy 要求显式 TLS1.2+、禁弱套件、默认不允许跳过证书校验。
func DefaultTLSDGPolicy() TLSDGPolicy {
	return TLSDGPolicy{
		RequireExplicitMinVersion: true,
		MinAllowedVersion:         tlsdgTLS12,
		ForbidWeakCiphers:         true,
		AllowScopedSkipVerify:     false,
	}
}

// 弱套件分类：1 弱加密（RC4/3DES/EXPORT/CBC-SHA1/无AEAD），2 NULL/匿名。
var tlsdgCipherClass = map[uint16]int{
	0x0001: 2, 0x0002: 2, // NULL_MD5 / NULL_SHA
	0x0003: 1,            // EXPORT_RC4_40
	0x0004: 1, 0x0005: 1, // RC4_128
	0x0006: 1,            // EXPORT_RC2_40
	0x0008: 1,            // EXPORT_DES40
	0x0009: 1,            // DES
	0x000A: 1,            // 3DES_EDE
	0x000B: 2,            // DH_anon_EXPORT_RC4_40
	0x002F: 1, 0x0035: 1, // RSA_AES_CBC_SHA(SHA1)
	0x0034: 2, 0x003A: 2, 0x006C: 2, 0x006D: 2, // anon AES
	0x008C: 1, 0x008D: 1, // RSA_AES_CBC_SHA256/384 无 AEAD
	0xC011: 1, // ECDHE_RSA_RC4_128
	0xC012: 1, // ECDHE_RSA_3DES
}

// TLSDGEvaluate 校验 TLS 配置视图。
func TLSDGEvaluate(cfg TLSDGView, policy TLSDGPolicy) (safe bool, findings []TLSDGFinding) {
	if cfg.InsecureSkipVerify {
		scoped := policy.AllowScopedSkipVerify && len(cfg.BypassScopeHosts) > 0
		if !scoped {
			if len(cfg.BypassScopeHosts) == 0 {
				findings = append(findings, TLSDGFinding{Reason: TLSDGReasonBypassTooBroad, Detail: "global"})
			}
			findings = append(findings, TLSDGFinding{Reason: TLSDGReasonSkipVerify})
		}
	}

	if cfg.HasPeerCertHook && !cfg.PeerCertHookEnforces {
		findings = append(findings, TLSDGFinding{Reason: TLSDGReasonHookNotEnforcing, Detail: "peer-certificate"})
	}
	if cfg.HasConnectionHook && !cfg.ConnectionHookEnforces {
		findings = append(findings, TLSDGFinding{Reason: TLSDGReasonHookNotEnforcing, Detail: "connection"})
	}

	if policy.RequireExplicitMinVersion && cfg.MinVersion == 0 {
		findings = append(findings, TLSDGFinding{Reason: TLSDGReasonMinVersionUnset})
	}
	switch cfg.MinVersion {
	case 0:
		// 未设置已单独记录
	case tlsdgSSL30, tlsdgTLS10, tlsdgTLS11:
		findings = append(findings, TLSDGFinding{Reason: TLSDGReasonMinVersionLow,
			Detail: tlsdgVersionName(cfg.MinVersion)})
	case tlsdgTLS12, tlsdgTLS13:
		// 合规
	default:
		findings = append(findings, TLSDGFinding{Reason: TLSDGReasonMinVersionLow, Detail: "unknown"})
	}
	if cfg.MaxVersion != 0 && cfg.MinVersion != 0 && cfg.MaxVersion < cfg.MinVersion {
		findings = append(findings, TLSDGFinding{Reason: TLSDGReasonMaxBelowMin})
	}

	if policy.ForbidWeakCiphers {
		for _, id := range cfg.CipherSuites {
			switch tlsdgCipherClass[id] {
			case 2:
				findings = append(findings, TLSDGFinding{Reason: TLSDGReasonNullAnonCipher,
					Detail: tlsdgCipherHex(id)})
			case 1:
				findings = append(findings, TLSDGFinding{Reason: TLSDGReasonWeakCipher,
					Detail: tlsdgCipherHex(id)})
			}
		}
	}

	if cfg.RenegotiationFreely {
		findings = append(findings, TLSDGFinding{Reason: TLSDGReasonRenegotiationOpen})
	}
	return len(findings) == 0, findings
}

func tlsdgVersionName(v uint16) string {
	switch v {
	case tlsdgSSL30:
		return "SSL3.0"
	case tlsdgTLS10:
		return "TLS1.0"
	case tlsdgTLS11:
		return "TLS1.1"
	case tlsdgTLS12:
		return "TLS1.2"
	case tlsdgTLS13:
		return "TLS1.3"
	}
	return "unknown"
}

func tlsdgCipherHex(id uint16) string {
	const hexd = "0123456789abcdef"
	b := []byte{'0', 'x'}
	for shift := 12; shift >= 0; shift -= 4 {
		b = append(b, hexd[(id>>uint(shift))&0xF])
	}
	return string(b)
}
