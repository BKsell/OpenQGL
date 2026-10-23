package main

// websocketupgradeguard.go —— WebSocket 升级握手的来源/目标校验与跨协议劫持防护。
//
// 背景：
//   启动器内嵌的 WebView/更新页可能发起 ws/wss 连接。WebSocket 不受同源策略完全约束，服务端若不
//   校验 Origin，任意网页可驱动受害者浏览器向其建立跨站 WebSocket（Cross-Site WebSocket Hijacking）；
//   此外：
//     - wss 页面发起明文 ws（混合内容降级，可被中间人注入帧）；
//     - 连接目标是 localhost/内网（把浏览器当跳板打本地服务，DNS rebinding 变体）；
//     - Sec-WebSocket-Protocol 被塞入 CRLF/超长值做头注入，或用子协议偷带凭据；
//     - 目标主机未在允许集合。
//   纯字符串/范围判定，IP 分类复用 HSClassifyIP4，不使用正则。

const (
	WSReasonOriginNotAllowed   = "websocket-origin-not-allowed"
	WSReasonMixedContent       = "websocket-plaintext-ws-from-secure-context"
	WSReasonTargetLocal        = "websocket-target-local-or-private"
	WSReasonHostNotAllowed     = "websocket-host-not-in-allowlist"
	WSReasonSubprotocolCRLF    = "websocket-subprotocol-header-crlf"
	WSReasonSubprotocolTooLong = "websocket-subprotocol-value-too-long"
	WSReasonBadScheme          = "websocket-url-scheme-not-ws-wss"
)

// WSFinding 记录一处 WebSocket 风险。
type WSFinding struct {
	Reason string
	Detail string
}

// WSPolicy 升级策略。
type WSPolicy struct {
	AllowedOrigins map[string]bool
	AllowedHosts   map[string]bool
	SecureContext  bool // 页面是否处于安全上下文（https/wss/受信本地）
	AllowPrivate   bool
	MaxSubprotoLen int
}

// DefaultWSPolicy 返回带默认长度上限的策略。
func DefaultWSPolicy() WSPolicy {
	return WSPolicy{
		AllowedOrigins: map[string]bool{},
		AllowedHosts:   map[string]bool{},
		MaxSubprotoLen: 256,
	}
}

// WSAuditUpgrade 审计一次升级请求。
// urlScheme 为 "ws"/"wss"；host 为主机名或 IP；origin 为页面 Origin 头；subprotocol 为该头原值。
func WSAuditUpgrade(policy WSPolicy, urlScheme, host, ip, origin, subprotocol string) (safe bool, findings []WSFinding) {
	scheme := wsLower(urlScheme)
	if scheme != "ws" && scheme != "wss" {
		findings = append(findings, WSFinding{Reason: WSReasonBadScheme, Detail: urlScheme})
	}

	if origin == "" || !policy.AllowedOrigins[origin] {
		findings = append(findings, WSFinding{Reason: WSReasonOriginNotAllowed, Detail: origin})
	}

	if policy.SecureContext && scheme == "ws" {
		findings = append(findings, WSFinding{Reason: WSReasonMixedContent})
	}

	if host != "" && len(policy.AllowedHosts) > 0 && !policy.AllowedHosts[wsLower(host)] {
		findings = append(findings, WSFinding{Reason: WSReasonHostNotAllowed, Detail: host})
	}

	// 目标 IP 落入本地/私域（连接公网服务场景）
	if ip != "" && !policy.AllowPrivate {
		switch HSClassifyIP4(ip) {
		case HSIPLoopback, HSIPLinkLocal, HSIPPrivate:
			findings = append(findings, WSFinding{Reason: WSReasonTargetLocal, Detail: ip})
		}
	}

	if subprotocol != "" {
		for i := 0; i < len(subprotocol); i++ {
			if subprotocol[i] == '\r' || subprotocol[i] == '\n' {
				findings = append(findings, WSFinding{Reason: WSReasonSubprotocolCRLF})
				break
			}
		}
		if policy.MaxSubprotoLen > 0 && len(subprotocol) > policy.MaxSubprotoLen {
			findings = append(findings, WSFinding{Reason: WSReasonSubprotocolTooLong,
				Detail: wsItoa(len(subprotocol))})
		}
	}

	return len(findings) == 0, findings
}

func wsLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func wsItoa(i int) string {
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

// WSHasReason 判定结果含某类问题。
func WSHasReason(findings []WSFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
