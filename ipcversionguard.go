package main

// ipcversionguard.go —— renderer↔主进程 IPC 协议版本/能力协商与降级攻击守卫。
//
// 背景：
//   Wails/Electron 的渲染进程（加载远程/本地 Web 内容）通过绑定调用主进程高权限方法。协议采用
//   "版本 + 方法名 + 载荷"协商，若不强制校验，可被恶意/被劫持的渲染面利用：
//     - 版本降级：渲染端声明一个旧协议版本，绕过新版才加入的参数校验（downgrade attack）；
//     - 未来版本：声明一个高于主进程的版本号（版本回滚/伪造客户端）；
//     - 方法在该版本不存在或已废弃，却仍被路由到"通用透传"原语；
//     - 同一条会话中途换版本（首包 v3、后续 v1），绕过按首包建立的策略；
//     - 请求来源 frame origin 与绑定期望不一致；请求缺 nonce/nonce 重放。
//   本模块是纯协商状态机：喂入握手版本与每帧 (method,version,nonce,origin)，返回是否放行；
//   不触碰真实 IPC 传输，不使用正则。

const (
	IPCVReasonVersionTooOld      = "ipc-protocol-version-downgrade"
	IPCVReasonVersionTooNew      = "ipc-protocol-version-unknown-future"
	IPCVReasonVersionChanged     = "ipc-protocol-version-changed-mid-session"
	IPCVReasonMethodNotInVersion = "ipc-method-unavailable-in-negotiated-version"
	IPCVReasonDeprecatedMethod   = "ipc-method-deprecated"
	IPCVReasonOriginMismatch     = "ipc-frame-origin-mismatch"
	IPCVReasonMissingNonce       = "ipc-frame-missing-nonce"
	IPCVReasonNonceReplay        = "ipc-frame-nonce-replay"
	IPCVReasonBeforeHandshake    = "ipc-frame-before-handshake"
)

// IPCVMethod 描述一个绑定方法在协议版本中的可用性。
type IPCVMethod struct {
	Name       string
	MinVersion int
	MaxVersion int // 0 表示不设上限
	Deprecated bool
}

// IPCVPolicy 协商策略。
type IPCVPolicy struct {
	MinVersion     int
	CurrentVersion int
	AllowedOrigin  string
	Methods        map[string]IPCVMethod
}

// IPCVFinding 记录一处 IPC 协商风险。
type IPCVFinding struct {
	Reason string
	Detail string
}

// IPCVSession 是一条 IPC 会话的协商状态。
type IPCVSession struct {
	policy     IPCVPolicy
	version    int
	handshaken bool
	seenNonce  map[string]bool
}

// NewIPCVSession 创建会话（尚未握手）。
func NewIPCVSession(policy IPCVPolicy) *IPCVSession {
	return &IPCVSession{policy: policy, seenNonce: map[string]bool{}}
}

// Handshake 处理渲染端声明的协议版本，返回是否接受。
func (s *IPCVSession) Handshake(clientVersion int) (ok bool, findings []IPCVFinding) {
	if clientVersion < s.policy.MinVersion {
		return false, []IPCVFinding{{Reason: IPCVReasonVersionTooOld,
			Detail: ipcvItoa(clientVersion)}}
	}
	if clientVersion > s.policy.CurrentVersion {
		return false, []IPCVFinding{{Reason: IPCVReasonVersionTooNew,
			Detail: ipcvItoa(clientVersion)}}
	}
	s.version = clientVersion
	s.handshaken = true
	return true, nil
}

// IPCVFrame 是一帧调用。
type IPCVFrame struct {
	Method string
	Nonce  string
	Origin string
}

// HandleFrame 在握手后校验每帧。
func (s *IPCVSession) HandleFrame(fr IPCVFrame) (ok bool, findings []IPCVFinding) {
	if !s.handshaken {
		return false, []IPCVFinding{{Reason: IPCVReasonBeforeHandshake}}
	}

	// 帧内若显式带版本（这里用方法上的隐含约束），不允许与协商版本不一致——
	// 通过方法在协商版本下的可用性体现。
	if fr.Origin != s.policy.AllowedOrigin {
		findings = append(findings, IPCVFinding{Reason: IPCVReasonOriginMismatch,
			Detail: fr.Origin})
	}
	if fr.Nonce == "" {
		findings = append(findings, IPCVFinding{Reason: IPCVReasonMissingNonce})
	} else if s.seenNonce[fr.Nonce] {
		findings = append(findings, IPCVFinding{Reason: IPCVReasonNonceReplay,
			Detail: fr.Nonce})
	} else {
		s.seenNonce[fr.Nonce] = true
	}

	m, known := s.policy.Methods[fr.Method]
	if !known {
		findings = append(findings, IPCVFinding{Reason: IPCVReasonMethodNotInVersion,
			Detail: fr.Method})
	} else {
		if s.version < m.MinVersion {
			findings = append(findings, IPCVFinding{Reason: IPCVReasonVersionTooOld,
				Detail: fr.Method})
		}
		if m.MaxVersion > 0 && s.version > m.MaxVersion {
			findings = append(findings, IPCVFinding{Reason: IPCVReasonMethodNotInVersion,
				Detail: fr.Method})
		}
		if m.Deprecated {
			findings = append(findings, IPCVFinding{Reason: IPCVReasonDeprecatedMethod,
				Detail: fr.Method})
		}
	}

	return len(findings) == 0, findings
}

// RenegotiateVersion 处理会话中途的版本变更（应拒绝，防止先高后低绕过）。
func (s *IPCVSession) RenegotiateVersion(newVersion int) (ok bool, findings []IPCVFinding) {
	if !s.handshaken {
		return s.Handshake(newVersion)
	}
	if newVersion != s.version {
		return false, []IPCVFinding{{Reason: IPCVReasonVersionChanged,
			Detail: ipcvItoa(s.version) + "->" + ipcvItoa(newVersion)}}
	}
	return true, nil
}

// NegotiatedVersion 返回已协商版本（未握手为 -1）。
func (s *IPCVSession) NegotiatedVersion() int {
	if !s.handshaken {
		return -1
	}
	return s.version
}

func ipcvItoa(i int) string {
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

// IPCVHas 判定结果含某类问题。
func IPCVHas(findings []IPCVFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
