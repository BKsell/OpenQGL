package main

// jwksguard.go —— JWT / JWKS 信任校验守卫。
//
// 背景：
//   启动器在微软/Mojang 及第三方登录（外置账号 Yggdrasil、自定义皮肤站）中会接触令牌与
//   JWKS 公钥端点。信任这些材料前若不校验，常见攻击有：
//     - alg=none：去掉签名段即可伪造任意身份；
//     - 算法混淆：服务端用 RSA 公钥当 HMAC 密钥，攻击者用公钥自签 HS256；
//     - kid 注入：kid 里带路径/命令/空值，诱导服务端取错或触发危险逻辑；
//     - 过期 / nbf 未到 / 缺 exp 的长期令牌；
//     - iss/aud 不匹配导致令牌混用（A 服务令牌打到 B 服务）；
//     - HMAC 共享密钥过短；JWK 用弱 kty/oct 或直接内联对称私钥。
//   本模块只做"在验签前应先满足的结构与声明校验"，纯字节解析，不依赖正则，也不做真正的
//   密码学验签（那是验签库职责），输出结论供登录链路据此快速拒绝。

import (
	"strings"
)

const (
	JWKSReasonAlgNone            = "jwks-alg-none"
	JWKSReasonAlgMissing         = "jwks-alg-missing"
	JWKSReasonAlgConfusion       = "jwks-algorithm-confusion"
	JWKSReasonUnsupportedAlg     = "jwks-unsupported-alg"
	JWKSReasonBadStructure       = "jwts-bad-structure"
	JWKSReasonHeaderNotJSON      = "jwks-header-not-json-object"
	JWKSReasonKidUnsafe          = "jwks-kid-unsafe"
	JWKSReasonExpired            = "jwts-token-expired"
	JWKSReasonNotBeforeFuture    = "jwts-nbf-in-future"
	JWKSReasonMissingExp         = "jwts-missing-exp"
	JWKSReasonIssuerMismatch     = "jwts-issuer-mismatch"
	JWKSReasonAudienceMissing    = "jwts-audience-missing"
	JWKSReasonWeakHMACSecret     = "jwks-weak-hmac-secret"
	JWKSReasonJWKWeakKty         = "jwks-jwk-weak-kty"
	JWKSReasonJWKMissingMaterial = "jwks-jwk-missing-material"
)

// JWTSPolicy 声明校验策略。
type JWTSPolicy struct {
	ExpectedIssuer          string   // 期望 iss；空表示不校验
	ExpectedAudiences       []string // 接受的 aud 列表；空表示不校验
	RequireExp              bool
	RequireKidForAsymmetric bool
	AllowedAlgs             map[string]bool // 允许的 alg 白名单
	NowUnix                 int64           // 当前时间，<=0 时由调用方保证传 exp/nbf 已比对
	MinHMACSecretLen        int
}

// JWTSFinding 记录一处令牌/JWK 风险。
type JWTSFinding struct {
	Reason string
	Detail string
}

// DefaultJWTSPolicy 返回默认策略：允许非对称算法与 HS256，拒绝 none，要求 exp/kid。
func DefaultJWTSPolicy() JWTSPolicy {
	return JWTSPolicy{
		RequireExp:              true,
		RequireKidForAsymmetric: true,
		MinHMACSecretLen:        32,
		AllowedAlgs: map[string]bool{
			"RS256": true, "RS384": true, "RS512": true,
			"ES256": true, "ES384": true, "ES512": true,
			"PS256": true, "PS384": true, "PS512": true,
			"EdDSA": true, "HS256": true,
		},
	}
}

// jwtsSegments 把 compact JWT 按 '.' 切成最多三段。
func jwtsSegments(token string) ([]string, bool) {
	t := strings.TrimSpace(token)
	if t == "" {
		return nil, false
	}
	var segs []string
	start := 0
	for i := 0; i < len(t); i++ {
		if t[i] == '.' {
			segs = append(segs, t[start:i])
			start = i + 1
		}
	}
	segs = append(segs, t[start:])
	if len(segs) != 3 {
		return segs, false
	}
	for _, s := range segs {
		if s == "" {
			return segs, false
		}
	}
	return segs, true
}

// jwtsIsAsymmetric 判断 alg 是否非对称（需要 JWKS 公钥）。
func jwtsIsAsymmetric(alg string) bool {
	a := strings.ToUpper(alg)
	switch {
	case strings.HasPrefix(a, "RS"), strings.HasPrefix(a, "ES"),
		strings.HasPrefix(a, "PS"), a == "EDDSA":
		return true
	}
	return false
}

// jwtsKidSafe 校验 kid 不含路径穿越、空白、控制字符。
func jwtsKidSafe(kid string) bool {
	if kid == "" {
		return false
	}
	for i := 0; i < len(kid); i++ {
		c := kid[i]
		if c <= 0x20 || c == 0x7F || c == '/' || c == '\\' {
			return false
		}
	}
	if strings.Contains(kid, "..") {
		return false
	}
	return true
}

// JWTSValidateHeader 在验签前校验 JWT 头部与结构。
// headerJSON 为已解码的 header 段对象字段（由调用方 base64+json 解析后传入）。
func JWTSValidateHeader(alg, kid string, policy JWTSPolicy) (safe bool, findings []JWTSFinding) {
	a := strings.TrimSpace(alg)
	if a == "" {
		findings = append(findings, JWTSFinding{Reason: JWKSReasonAlgMissing})
	} else {
		au := strings.ToUpper(a)
		if au == "NONE" {
			findings = append(findings, JWTSFinding{Reason: JWKSReasonAlgNone})
		}
		if policy.AllowedAlgs != nil && !policy.AllowedAlgs[au] {
			findings = append(findings, JWTSFinding{Reason: JWKSReasonUnsupportedAlg, Detail: a})
		}
	}
	if policy.RequireKidForAsymmetric && jwtsIsAsymmetric(a) && !jwtsKidSafe(kid) {
		findings = append(findings, JWTSFinding{Reason: JWKSReasonKidUnsafe, Detail: kid})
	}
	return len(findings) == 0, findings
}

// JWTSValidateClaims 校验时间与主体声明。exp/nbf 为 Unix 秒；aud 可为单值或多值。
func JWTSValidateClaims(iss string, aud []string, exp, nbf int64, hasExp bool, policy JWTSPolicy) (safe bool, findings []JWTSFinding) {
	if policy.RequireExp && !hasExp {
		findings = append(findings, JWTSFinding{Reason: JWKSReasonMissingExp})
	}
	if hasExp && policy.NowUnix > 0 && exp > 0 && exp < policy.NowUnix {
		findings = append(findings, JWTSFinding{Reason: JWKSReasonExpired,
			Detail: itoaJWTS(exp)})
	}
	if policy.NowUnix > 0 && nbf > policy.NowUnix {
		findings = append(findings, JWTSFinding{Reason: JWKSReasonNotBeforeFuture,
			Detail: itoaJWTS(nbf)})
	}
	if policy.ExpectedIssuer != "" && iss != policy.ExpectedIssuer {
		findings = append(findings, JWTSFinding{Reason: JWKSReasonIssuerMismatch, Detail: iss})
	}
	if len(policy.ExpectedAudiences) > 0 {
		ok := false
		for _, want := range policy.ExpectedAudiences {
			for _, got := range aud {
				if got == want {
					ok = true
					break
				}
			}
			if ok {
				break
			}
		}
		if !ok {
			findings = append(findings, JWTSFinding{Reason: JWKSReasonAudienceMissing})
		}
	}
	return len(findings) == 0, findings
}

// JWKSValidateHMACSecret 校验对称签名共享密钥强度，防弱密钥。
func JWKSValidateHMACSecret(secret string, policy JWTSPolicy) (safe bool, findings []JWTSFinding) {
	if len(secret) < policy.MinHMACSecretLen {
		findings = append(findings, JWTSFinding{Reason: JWKSReasonWeakHMACSecret,
			Detail: "len=" + itoaJWTS(int64(len(secret)))})
	}
	return len(findings) == 0, findings
}

// JWKSValidateKeyMaterial 粗检单个 JWK 是否携带可用的非对称公钥材料。
// kty 为 RSA/EC 时，n/e（RSA）或 crv/x（EC）必须存在；kty=oct 是对称密钥不应出现在公钥集。
func JWKSValidateKeyMaterial(kty, n, e, crv, x, y string) (safe bool, findings []JWTSFinding) {
	k := strings.ToUpper(strings.TrimSpace(kty))
	if k == "OCT" {
		findings = append(findings, JWTSFinding{Reason: JWKSReasonJWKWeakKty, Detail: "oct-in-public-jwks"})
		return false, findings
	}
	switch k {
	case "RSA":
		if n == "" || e == "" {
			findings = append(findings, JWTSFinding{Reason: JWKSReasonJWKMissingMaterial, Detail: "rsa-needs-n,e"})
		}
	case "EC":
		if crv == "" || x == "" || y == "" {
			findings = append(findings, JWTSFinding{Reason: JWKSReasonJWKMissingMaterial, Detail: "ec-needs-crv,x,y"})
		}
	case "OKP":
		if crv == "" || x == "" {
			findings = append(findings, JWTSFinding{Reason: JWKSReasonJWKMissingMaterial, Detail: "okp-needs-crv,x"})
		}
	default:
		findings = append(findings, JWTSFinding{Reason: JWKSReasonJWKWeakKty, Detail: kty})
	}
	return len(findings) == 0, findings
}

func itoaJWTS(i int64) string {
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
