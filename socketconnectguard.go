package main

// socketconnectguard.go —— 出向 TCP 连接目标复核与"解析后固定（DNS pinning）"防重绑定。
//
// 背景：
//   经典 DNS rebinding：程序先 getaddrinfo 拿到 IP 做安全校验（允许），随后真正 connect 时又解析了
//   一次主机名，攻击者在两次解析之间切换 A 记录，让连接落到内网/环回。此外，对"裸 IP"直连也需复核：
//     - 禁止连接到环回/链路本地（云元数据 169.254.169.254）/未指定地址 0.0.0.0；
//     - 端口必须落在显式允许集合（不允许 0、>65535、内部管理端口对外名的复用）；
//     - connect 用的 IP 必须就是"校验通过并固定"的那个地址（pin once, connect same）；
//     - 主机名解析结果在允许有效期内复用，避免二次解析漂移；
//   IP 分类复用 hostshijackguard 的 HSClassifyIP4；纯判定，不发起网络调用，不用正则。

const (
	SCReasonIPNotPinned    = "socket-connect-ip-not-resolved-and-pinned"
	SCReasonIPChanged      = "socket-connect-pinned-ip-changed"
	SCReasonBlockedScope   = "socket-connect-target-scope-blocked"
	SCReasonPortNotAllowed = "socket-connect-port-not-allowed"
	SCReasonUnspecifiedIP  = "socket-connect-to-unspecified-address"
	SCReasonPinExpired     = "socket-connect-pinned-address-expired"
)

// SCFinding 记录一处连接风险。
type SCFinding struct {
	Reason string
	Host   string
	IP     string
	Port   int
}

// SCAllowedPort 判定端口是否在允许集合。
func SCAllowedPort(port int, allowed []int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	for _, p := range allowed {
		if p == port {
			return true
		}
	}
	return false
}

// SCBlockedScopeIP 判定某 IP 是否属于禁止直连的范围（环回/链路本地/私有/未指定/保留）。
// 连接外部更新源时调用；内部局域网服务器（用户自填）由调用方通过 allowPrivate 放行。
func SCBlockedScopeIP(ip string, allowPrivate bool) (blocked bool, scope string) {
	c := HSClassifyIP4(ip)
	switch c {
	case HSIPLoopback:
		return true, "loopback"
	case HSIPLinkLocal:
		return true, "link-local"
	case HSIPPrivate:
		return !allowPrivate, "private"
	case HSIPInvalid:
		return true, "unspecified-or-invalid"
	}
	return false, ""
}

// SCPin 是一次"解析后固定"的结果。
type SCPin struct {
	Host      string
	IP        string
	Port      int
	ValidTick uint64
	TTL       uint64
}

// SCPinValid 判断固定项在某时刻是否仍有效。
func (p SCPin) PinValid(tick uint64) bool {
	if p.TTL == 0 {
		return false
	}
	return tick >= p.ValidTick && tick <= p.ValidTick+p.TTL
}

// SCValidateConnect 校验真正 connect 的 (pin, ip, port, tick)。
func SCValidateConnect(pin SCPin, host, ip string, port int, tick uint64,
	allowedPorts []int, allowPrivate bool) (ok bool, findings []SCFinding) {

	if !SCAllowedPort(port, allowedPorts) {
		findings = append(findings, SCFinding{Reason: SCReasonPortNotAllowed,
			Host: host, IP: ip, Port: port})
	}
	if blocked, _ := SCBlockedScopeIP(ip, allowPrivate); blocked {
		findings = append(findings, SCFinding{Reason: SCReasonBlockedScope,
			Host: host, IP: ip, Port: port})
	}
	if pin.Host == "" || pin.IP == "" {
		findings = append(findings, SCFinding{Reason: SCReasonIPNotPinned,
			Host: host, IP: ip, Port: port})
		return false, findings
	}
	if !pin.PinValid(tick) {
		findings = append(findings, SCFinding{Reason: SCReasonPinExpired,
			Host: host, IP: ip, Port: port})
	}
	// 关键：connect 地址必须与固定地址一致，杜绝二次解析重绑定。
	if pin.IP != ip || pin.Host != host || pin.Port != port {
		findings = append(findings, SCFinding{Reason: SCReasonIPChanged,
			Host: host, IP: ip, Port: port})
	}
	return len(findings) == 0, findings
}

// SCHasReason 判定结果含某类问题。
func SCHasReason(findings []SCFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
