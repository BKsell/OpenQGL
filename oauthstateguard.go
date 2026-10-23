package main

// oauthstateguard.go —— OAuth/OIDC 登录回调 state 参数的 CSRF 绑定与单次使用守卫。
//
// 背景：
//   PKCE（既有 pkceguard）解决授权码截获，但跨站登录 CSRF 由 state 参数负责。state 处理缺陷：
//     - 发起登录不生成/不绑定 state，回调不校验，攻击者可把自己的授权码塞进受害者会话；
//     - state 可预测（顺序/时间戳/短串），被猜解；
//     - state 可重放（同一 state 多次回调成功）；
//     - state 不绑定发起方（会话、浏览器随机串、最终 redirect_uri），跨设备/跨端点套用；
//     - 回调 state 与发起记录不匹配仍放行。
//   纯状态机判定：登记发起记录、消费回调 state；不生成真实随机数（由调用方提供），不用正则。

import "sync"

const (
	OSReasonStateMissing     = "oauth-state-missing-on-callback"
	OSReasonStateUnknown     = "oauth-state-not-bound-to-a-login-attempt"
	OSReasonStateReplay      = "oauth-state-replayed"
	OSReasonStatePredictable = "oauth-state-too-short-or-predictable"
	OSReasonSessionMismatch  = "oauth-state-session-binding-mismatch"
	OSReasonRedirectMismatch = "oauth-state-redirect-binding-mismatch"
)

// OSMinStateLen 是 state 最小长度（字节）。
const OSMinStateLen = 16

// OSAttempt 是一次登录发起记录。
type OSAttempt struct {
	State       string
	SessionID   string
	RedirectURI string
	Consumed    bool
}

// OSStore 保存进行中的登录发起。
type OSStore struct {
	mu       sync.Mutex
	attempts map[string]OSAttempt
}

// NewOSStore 创建 store。
func NewOSStore() *OSStore {
	return &OSStore{attempts: map[string]OSAttempt{}}
}

// OSStateLooksRandom 粗判 state 不可预测性（长度下限 + 至少两类字符）。
func OSStateLooksRandom(state string) bool {
	if len(state) < OSMinStateLen {
		return false
	}
	hasLower, hasUpper, hasDigit := false, false, false
	for i := 0; i < len(state); i++ {
		c := state[i]
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}
	classes := 0
	if hasLower {
		classes++
	}
	if hasUpper {
		classes++
	}
	if hasDigit {
		classes++
	}
	return classes >= 2
}

// OSBegin 登记一次登录发起。
func (s *OSStore) OSBegin(a OSAttempt) (ok bool, reason string) {
	if !OSStateLooksRandom(a.State) {
		return false, OSReasonStatePredictable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts[a.State] = OSAttempt{State: a.State, SessionID: a.SessionID,
		RedirectURI: a.RedirectURI}
	return true, ""
}

// OSFinish 消费回调 state，校验绑定与单次使用。
func (s *OSStore) OSFinish(state, sessionID, redirectURI string) (ok bool, findings []string) {
	if state == "" {
		return false, []string{OSReasonStateMissing}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	a, exists := s.attempts[state]
	if !exists {
		return false, []string{OSReasonStateUnknown}
	}
	if a.Consumed {
		return false, []string{OSReasonStateReplay}
	}
	if a.SessionID != sessionID {
		findings = append(findings, OSReasonSessionMismatch)
	}
	if a.RedirectURI != redirectURI {
		findings = append(findings, OSReasonRedirectMismatch)
	}
	a.Consumed = true
	s.attempts[state] = a
	if len(findings) > 0 {
		return false, findings
	}
	return true, nil
}
