package main

// sessioncookieguard.go —— 会话/鉴权 Cookie 属性与生命周期守卫。
//
// 背景：
//   启动器会保存登录态（Mojang/Yggdrasil/自建验证服务）。承载会话令牌的 Cookie 若属性配置不当，会被
//   XSS 窃取（缺 HttpOnly）、被明文链路劫持（缺 Secure）、被跨站请求携带（SameSite 缺失），并存在：
//     - 会话固定（session fixation）：登录前后会话标识不变，攻击者预置的标识登录后仍有效；
//     - 永不过期的持久令牌（Expires 很远 / Max-Age 巨大）；
//     - 刷新令牌与会话令牌混用同一 Cookie；
//   纯属性判定，不解析真实网络，不使用正则。

const (
	SKReasonMissingHttpOnly  = "session-cookie-missing-httponly"
	SKReasonMissingSecure    = "session-cookie-missing-secure"
	SKReasonSameSiteWeak     = "session-cookie-samesite-weak-or-missing"
	SKReasonNeverExpires     = "session-cookie-effectively-never-expires"
	SKReasonFixation         = "session-cookie-not-rotated-after-login"
	SKReasonRefreshInSession = "session-cookie-refresh-token-mixed-in-session"
	SKReasonEmptyValue       = "session-cookie-empty-value"
)

// SKMaxAgeHardLimit 是会话 Cookie 允许的 Max-Age 上限（秒，30 天）。
const SKMaxAgeHardLimit = 30 * 24 * 3600

// SKCookie 描述一条会话 Cookie 的属性。
type SKCookie struct {
	Name           string
	Value          string
	IsSessionToken bool
	IsRefreshToken bool
	HttpOnly       bool
	Secure         bool
	SameSite       string // "Strict" / "Lax" / "None" / ""
	MaxAgeSec      int    // -1 会话期；0 未设置；>0 持久秒数
}

// SKFinding 记录一处 Cookie 风险。
type SKFinding struct {
	Reason string
	Name   string
}

// SKAuditCookie 审计单条会话 Cookie。
func SKAuditCookie(c SKCookie) (safe bool, findings []SKFinding) {
	if c.Value == "" {
		findings = append(findings, SKFinding{Reason: SKReasonEmptyValue, Name: c.Name})
	}
	if !c.HttpOnly {
		findings = append(findings, SKFinding{Reason: SKReasonMissingHttpOnly, Name: c.Name})
	}
	if !c.Secure {
		findings = append(findings, SKFinding{Reason: SKReasonMissingSecure, Name: c.Name})
	}
	ss := skLower(c.SameSite)
	if ss != "strict" && ss != "lax" {
		findings = append(findings, SKFinding{Reason: SKReasonSameSiteWeak, Name: c.Name})
	}
	if c.MaxAgeSec > SKMaxAgeHardLimit {
		findings = append(findings, SKFinding{Reason: SKReasonNeverExpires, Name: c.Name})
	}
	if c.IsSessionToken && c.IsRefreshToken {
		findings = append(findings, SKFinding{Reason: SKReasonRefreshInSession, Name: c.Name})
	}
	return len(findings) == 0, findings
}

// SKCheckRotation 检测会话固定：登录后会话标识必须变化。
// preID 为登录前 Cookie 值/派生标识，postID 为登录后。
func SKCheckRotation(preID, postID string) (rotated bool, findings []SKFinding) {
	if preID == "" {
		return true, nil // 登录前无会话，属正常
	}
	if preID == postID {
		return false, []SKFinding{{Reason: SKReasonFixation}}
	}
	return true, nil
}

func skLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

// SKHasReason 判定结果含某类问题。
func SKHasReason(findings []SKFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
