package main

// hostshijackguard.go —— hosts 文件/DNS 重绑定本地覆盖导致的受信主机映射劫持检测。
//
// 背景：
//   启动器若用主机名连接受信端点（Mojang、登录、自有更新源），而本机 hosts 文件或本地 DNS 把该
//   主机名映射到环回/内网/陌生地址，就会在"名字正确"的情况下连到攻击者控制的服务器（配合本地
//   起的假服务完成凭据收割或下发恶意文件）。与 dnsrebinding（TTL=0 快速换 IP）不同，这里检测的是
//   "静态、持久的名字->地址映射异常"：
//     - 受信主机名被解析到环回/链路本地/私有网段（公网受信域名不应指向内网）；
//     - 一个受信主机名的多条 A 记录分属互不相干的网段（含公网又含内网）；
//     - hosts 中出现受信域名的手工映射行（无论指向哪里，都应告警/忽略并走真实 DNS）；
//     - 解析结果在短时间内变到不同 /24（与历史基线漂移）。
//   本模块只对"主机名 + 已解析 IP 列表 + hosts 行"做判定，IP 分类自实现，不发起 DNS、不用正则。

const (
	HSReasonTrustedHostToLoopback = "trusted-host-resolves-to-loopback"
	HSReasonTrustedHostToPrivate  = "trusted-host-resolves-to-private-range"
	HSReasonMixedScopeRecords     = "trusted-host-mixed-public-private-records"
	HSReasonHostsOverride         = "trusted-host-present-in-hosts-file"
	HSReasonBaselineDrift         = "trusted-host-resolution-baseline-drift"
	HSReasonLinkLocal             = "trusted-host-resolves-to-link-local"
)

// HSFinding 记录一处主机映射风险。
type HSFinding struct {
	Reason string
	Host   string
	IP     string
}

// HSIPClass 表示 IP 地址范围类别。
type HSIPClass int

const (
	HSIPInvalid HSIPClass = iota
	HSIPLoopback
	HSIPPrivate
	HSIPLinkLocal
	HSIPPublic
)

// HSClassifyIP4 分类一个 IPv4 字符串（不支持主机名）。
func HSClassifyIP4(ip string) HSIPClass {
	var parts [4]int
	n := 0
	cur := 0
	hasDigit := false
	for i := 0; i <= len(ip); i++ {
		if i == len(ip) || ip[i] == '.' {
			if !hasDigit || cur > 255 || n > 3 {
				return HSIPInvalid
			}
			parts[n] = cur
			n++
			cur = 0
			hasDigit = false
			if i == len(ip) {
				break
			}
			continue
		}
		if ip[i] < '0' || ip[i] > '9' {
			return HSIPInvalid
		}
		cur = cur*10 + int(ip[i]-'0')
		hasDigit = true
		if cur > 255 {
			return HSIPInvalid
		}
	}
	if n != 4 {
		return HSIPInvalid
	}
	a, b := parts[0], parts[1]
	switch {
	case a == 0:
		return HSIPInvalid
	case a == 127:
		return HSIPLoopback
	case a == 10:
		return HSIPPrivate
	case a == 169 && b == 254:
		return HSIPLinkLocal
	case a == 172 && b >= 16 && b <= 31:
		return HSIPPrivate
	case a == 192 && b == 168:
		return HSIPPrivate
	case a == 100 && b >= 64 && b <= 127:
		return HSIPPrivate // CGNAT
	case a >= 224:
		return HSIPInvalid // 组播/保留
	}
	return HSIPPublic
}

// HSAuditResolution 审计某受信主机名的解析结果。
// trustedIsPublic=true 表示该主机按设计应是公网端点（则内网/环回映射即异常）。
func HSAuditResolution(host string, ips []string, trustedIsPublic bool) (safe bool, findings []HSFinding) {
	hasPublic := false
	hasPrivate := false
	for _, ip := range ips {
		c := HSClassifyIP4(ip)
		switch c {
		case HSIPInvalid:
			continue
		case HSIPLoopback:
			findings = append(findings, HSFinding{Reason: HSReasonTrustedHostToLoopback,
				Host: host, IP: ip})
			if trustedIsPublic {
				hasPrivate = true
			}
		case HSIPLinkLocal:
			findings = append(findings, HSFinding{Reason: HSReasonLinkLocal, Host: host, IP: ip})
			hasPrivate = true
		case HSIPPrivate:
			findings = append(findings, HSFinding{Reason: HSReasonTrustedHostToPrivate,
				Host: host, IP: ip})
			hasPrivate = true
		case HSIPPublic:
			hasPublic = true
		}
	}
	if trustedIsPublic && hasPublic && hasPrivate {
		findings = append(findings, HSFinding{Reason: HSReasonMixedScopeRecords, Host: host})
	}
	return len(findings) == 0, findings
}

// HSAuditHostsLines 检查 hosts 文件文本行中是否出现受信主机名覆盖。
// 传入逐行内容（调用方读取 hosts），本函数纯判定，不读文件系统。
func HSAuditHostsLines(lines []string, trustedHosts map[string]bool) (findings []HSFinding) {
	for _, line := range lines {
		trimmed := hsTrimComment(line)
		fields := hsFields(trimmed)
		if len(fields) < 2 {
			continue
		}
		for _, h := range fields[1:] {
			if trustedHosts[hsToLower(h)] {
				findings = append(findings, HSFinding{
					Reason: HSReasonHostsOverride, Host: hsToLower(h), IP: fields[0]})
			}
		}
	}
	return findings
}

// HSBaseline / HSDetectDrift 检测解析结果相对历史基线的网段漂移。
type HSBaseline struct {
	First16 int // 前两个八位组作为 /16 粗指纹
}

// HSBuildBaseline 从一个公网 IP 建基线。
func HSBuildBaseline(ip string) (HSBaseline, bool) {
	var a, b int
	if hsFirstTwo(ip, &a, &b) {
		return HSBaseline{First16: a*256 + b}, true
	}
	return HSBaseline{}, false
}

// HSDetectDrift 比较当前 IP 是否与基线同一 /16。
func HSDetectDrift(base HSBaseline, currentIP string) bool {
	var a, b int
	if !hsFirstTwo(currentIP, &a, &b) {
		return false
	}
	cur := a*256 + b
	return cur != base.First16
}

func hsFirstTwo(ip string, a, b *int) bool {
	var parts [2]int
	n := 0
	cur := 0
	hasDigit := false
	for i := 0; i <= len(ip); i++ {
		if i == len(ip) || ip[i] == '.' {
			if !hasDigit || cur > 255 {
				return false
			}
			if n < 2 {
				parts[n] = cur
			}
			n++
			cur = 0
			hasDigit = false
			if i == len(ip) {
				break
			}
			continue
		}
		if ip[i] < '0' || ip[i] > '9' {
			return false
		}
		cur = cur*10 + int(ip[i]-'0')
		hasDigit = true
	}
	if n != 4 {
		return false
	}
	*a, *b = parts[0], parts[1]
	return true
}

func hsTrimComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' {
			return line[:i]
		}
	}
	return line
}

func hsFields(s string) []string {
	var out []string
	cur := ""
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' || s[i] == '\t' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			if i == len(s) {
				break
			}
			continue
		}
		cur += string(s[i])
	}
	return out
}

func hsToLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

// HSHasReason 判定结果含某类问题。
func HSHasReason(findings []HSFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
