package main

// portbindguard.go —— 本地回跳/HTTP 服务的监听地址绑定守卫。
//
// 背景：
//   OAuth loopback 流程（RFC 8252）要在本机起一个临时 HTTP 服务接收 code。绑定到哪个网卡决定
//   "谁能把请求打进来"：
//     - 绑 0.0.0.0 / :: / 通配地址：局域网内任意设备、同子网攻击者都能向回调端口投送伪造 code
//       或做登录 CSRF；
//     - 绑到具体外网网卡 IP：同样暴露到网络；
//     - 只应绑 127.0.0.1 / ::1（loopback），且端口临时、收到即关；
//     - UPnP/端口映射、SO_REUSEADDR 抢占也会让"回跳端口"被他人先占用或复用。
//   本模块校验监听地址视图，纯字符串/布尔判定，不使用正则。

import "strings"

const (
	PBGReasonWildcardBind     = "loopback-wildcard-address-bind"
	PBGReasonNonLoopbackBind  = "loopback-non-loopback-interface-bind"
	PBGReasonIPv6Wildcard     = "loopback-ipv6-wildcard-bind"
	PBGReasonPrivilegedPort   = "loopback-privileged-fixed-port"
	PBGReasonPortForwarding   = "loopback-upnp-port-forwarding-enabled"
	PBGReasonReuseAddr        = "loopback-so-reuseaddr-on-callback"
	PBGReasonPersistentServer = "loopback-server-not-one-shot"
	PBGReasonMissingStateGate = "loopback-missing-csrf-state-gate"
)

// PBGBindView 描述本地回调服务的监听配置。
type PBGBindView struct {
	Host             string // net.Listen 的 host 部分
	Port             int
	IsLoopback       bool // 调用方已知的判定（与 host 二者结合）
	IPv6             bool
	UPnPPortForward  bool
	SOReuseAddr      bool
	OneShot          bool // 收到一次合法回调即关闭
	HasStateCSRFGate bool // 是否校验一次性 state
}

// PBGFinding 记录一处绑定风险。
type PBGFinding struct {
	Reason string
	Detail string
}

// PBGEvaluate 校验监听配置。loopback 回跳必须只绑回环、临时端口、一次性、带 state 闸门。
func PBGEvaluate(v PBGBindView) (safe bool, findings []PBGFinding) {
	host := strings.TrimSpace(strings.ToLower(v.Host))
	loopbackToken := host == "127.0.0.1" || host == "localhost" || host == "::1" ||
		strings.HasPrefix(host, "127.")

	switch {
	case host == "" || host == "0.0.0.0" || host == "*":
		findings = append(findings, PBGFinding{Reason: PBGReasonWildcardBind, Detail: host})
	case host == "::":
		findings = append(findings, PBGFinding{Reason: PBGReasonIPv6Wildcard, Detail: host})
	case loopbackToken:
		// loopback，合规
	case v.IsLoopback:
		// 调用方已确认该网卡为回环
	default:
		findings = append(findings, PBGFinding{Reason: PBGReasonNonLoopbackBind, Detail: host})
	}

	// 回跳不应固定占用特权/知名端口
	if v.Port > 0 && v.Port < 1024 {
		findings = append(findings, PBGFinding{Reason: PBGReasonPrivilegedPort, Detail: itoaPBG(v.Port)})
	}
	if v.UPnPPortForward {
		findings = append(findings, PBGFinding{Reason: PBGReasonPortForwarding})
	}
	if v.SOReuseAddr {
		findings = append(findings, PBGFinding{Reason: PBGReasonReuseAddr})
	}
	if !v.OneShot {
		findings = append(findings, PBGFinding{Reason: PBGReasonPersistentServer})
	}
	if !v.HasStateCSRFGate {
		findings = append(findings, PBGFinding{Reason: PBGReasonMissingStateGate})
	}
	return len(findings) == 0, findings
}

func itoaPBG(i int) string {
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
