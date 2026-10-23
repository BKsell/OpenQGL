package main

// hostnameguard.go —— 用户"加入服务器"所填主机名 / 地址的合法性与 SSRF 面校验。
//
// 背景：
//   多人游戏的"添加服务器"地址完全由用户 / 第三方服务器列表（可能来自不可信整合包）控制。
//   启动器 / 客户端会拿这个地址做连通性探测、服务器图标下载、MOTD 拉取等 HTTP 化操作。
//   危险形态：
//     1. 环回 / 私网 / 链路本地 / 云元数据地址，借启动器的网络能力打内网；
//     2. 非法或超长主机名（标签 >63、总长 >253）、含空白 / 控制字符 / 下划线误配；
//     3. 端口越界 / 非数字 / 前导零引发的解析差异；
//     4. 0.0.0.0、[::]、十进制 / 十六进制整数 IP、IPv4-mapped IPv6（::ffff:127.0.0.1）
//        等"绕过字符串黑名单"的等价环回写法；
//     5. userinfo、scheme 被塞进地址栏。
//
// 纯字符判定，不使用正则。

const (
	HNGReasonPrivateIP        = "hng-private-or-loopback-target"
	HNGReasonMetadataIP       = "hng-cloud-metadata-target"
	HNGReasonUnspecifiedIP    = "hng-unspecified-wildcard-address"
	HNGReasonMappedV4Loopback = "hng-ipv4-mapped-loopback"
	HNGReasonBadPort          = "hng-invalid-port"
	HNGReasonLabelTooLong     = "hng-dns-label-too-long"
	HNGReasonNameTooLong      = "hng-hostname-too-long"
	HNGReasonIllegalChar      = "hng-illegal-hostname-character"
	HNGReasonEmbeddedScheme   = "hng-scheme-or-userinfo-in-address"
	HNGReasonEmptyHost        = "hng-empty-host"
)

// HNGPolicy 控制地址校验严格度。
type HNGPolicy struct {
	ForbidPrivateTargets bool
	ForbidUnspecified    bool
	MaxHostnameLen       int
	MaxLabelLen          int
	PortMin              int
	PortMax              int
}

// HNGFinding 记录一处地址风险。
type HNGFinding struct {
	Reason string
	Host   string
	Port   string
	Detail string
}

// DefaultHNGPolicy 返回默认严格策略。
func DefaultHNGPolicy() HNGPolicy {
	return HNGPolicy{
		ForbidPrivateTargets: true,
		ForbidUnspecified:    true,
		MaxHostnameLen:       253,
		MaxLabelLen:          63,
		PortMin:              1,
		PortMax:              65535,
	}
}

// HNGSplitHostPort 拆 host 与 port；处理 IPv6 [::1]:25565。返回 host（不带方括号）、port、有无端口。
func HNGSplitHostPort(addr string) (host, port string, hasPort bool, ok bool) {
	a := addr
	if a == "" {
		return "", "", false, false
	}
	// 检出误塞 scheme / userinfo。
	for i := 0; i < len(a); i++ {
		if a[i] == '@' {
			return "", "", false, false
		}
	}
	if len(a) >= 2 && a[0] == '[' {
		cb := -1
		for i := 1; i < len(a); i++ {
			if a[i] == ']' {
				cb = i
				break
			}
		}
		if cb < 0 {
			return "", "", false, false
		}
		host = a[1:cb]
		rest := a[cb+1:]
		if rest == "" {
			return host, "", false, true
		}
		if rest[0] != ':' {
			return "", "", false, false
		}
		return host, rest[1:], true, true
	}
	// 裸 IPv6（含冒号但无方括号）：整个当 host，无端口。
	colonCount := 0
	for i := 0; i < len(a); i++ {
		if a[i] == ':' {
			colonCount++
		}
	}
	if colonCount >= 2 {
		return a, "", false, true
	}
	if colonCount == 1 {
		idx := -1
		for i := 0; i < len(a); i++ {
			if a[i] == ':' {
				idx = i
			}
		}
		return a[:idx], a[idx+1:], true, true
	}
	return a, "", false, true
}

// hngParsePort 纯数字端口，拒绝前导零歧义与越界。
func hngParsePort(s string, pol HNGPolicy) (int, bool) {
	if s == "" {
		return 0, false
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	v := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int(c-'0')
		if v > pol.PortMax {
			return 0, false
		}
	}
	if v < pol.PortMin {
		return 0, false
	}
	return v, true
}

// hngIsIntegerIP 检测十进制整数 IP（如 2130706433 == 127.0.0.1）。
func hngAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// hngIPv4MappedV6 检测 ::ffff:a.b.c.d 形态。
func hngIPv4MappedV6(g [8]uint16) (string, bool) {
	if g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 &&
		g[4] == 0 && g[5] == 0xffff {
		hi := g[6]
		lo := g[7]
		ip := [4]byte{byte(hi >> 8), byte(hi), byte(lo >> 8), byte(lo)}
		out := ""
		out += hngItoa(int(ip[0])) + "." + hngItoa(int(ip[1])) + "." +
			hngItoa(int(ip[2])) + "." + hngItoa(int(ip[3]))
		return out, true
	}
	return "", false
}

func hngItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// hngValidHostnameChars 校验 DNS 主机名字符（字母数字连字符；下划线单独宽松但记录）。
func hngValidHostnameChars(host string) bool {
	if host == "" {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 0x80 {
			// IDN 域名字节（UTF-8）放行，同形字面由 idnhomoglyphguard 负责。
			continue
		}
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if isAlnum || c == '-' || c == '.' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// HNGEvaluate 校验一个"加入服务器"地址。
func HNGEvaluate(addr string, pol HNGPolicy) []HNGFinding {
	var out []HNGFinding
	add := func(reason, detail string) {
		out = append(out, HNGFinding{Reason: reason, Host: addr, Detail: detail})
	}
	host, port, hasPort, ok := HNGSplitHostPort(addr)
	if !ok {
		add(HNGReasonEmbeddedScheme, "split-failed")
		return out
	}
	if host == "" {
		add(HNGReasonEmptyHost, "")
		return out
	}
	if hasPort {
		if _, ok := hngParsePort(port, pol); !ok {
			add(HNGReasonBadPort, port)
		}
	}

	// IPv4 字面量。
	if ip4, ok4 := drgParseIPv4(host); ok4 {
		cls, _ := drgClassifyIP(host)
		if pol.ForbidUnspecified && (ip4[0] == 0) {
			add(HNGReasonUnspecifiedIP, host)
		}
		if pol.ForbidPrivateTargets && cls != DRGClassPublic {
			if cls == DRGClassMetadata {
				add(HNGReasonMetadataIP, host)
			} else {
				add(HNGReasonPrivateIP, host)
			}
		}
		return out
	}
	// IPv6 字面量（含 ::ffff: 映射）。
	if g, ok6 := drgExpandIPv6(host); ok6 {
		if mapped, isMapped := hngIPv4MappedV6(g); isMapped {
			cls, _ := drgClassifyIP(mapped)
			if pol.ForbidPrivateTargets && cls != DRGClassPublic {
				add(HNGReasonMappedV4Loopback, mapped)
			}
			return out
		}
		cls, _ := drgClassifyIP(host)
		// 未指定 :: / ::0。
		allZero := true
		for _, x := range g {
			if x != 0 {
				allZero = false
			}
		}
		if pol.ForbidUnspecified && allZero {
			add(HNGReasonUnspecifiedIP, host)
		}
		if pol.ForbidPrivateTargets && cls != DRGClassPublic {
			add(HNGReasonPrivateIP, host)
		}
		return out
	}
	// 十进制整数 IP。
	if hngAllDigits(host) {
		add(HNGReasonPrivateIP, "integer-ip-literal")
		return out
	}
	// DNS 主机名。
	if len(host) > pol.MaxHostnameLen {
		add(HNGReasonNameTooLong, hngItoa(len(host)))
	}
	if !hngValidHostnameChars(host) {
		add(HNGReasonIllegalChar, "")
		return out
	}
	for _, label := range hngSplitLabelsHNG(host) {
		if len(label) > pol.MaxLabelLen {
			add(HNGReasonLabelTooLong, label)
		}
	}
	return out
}

// hngSplitLabelsHNG 按 '.' 切 DNS 标签（保留 UTF-8 原样，不做码点展开）。
func hngSplitLabelsHNG(host string) []string {
	out := []string{}
	cur := ""
	for i := 0; i < len(host); i++ {
		if host[i] == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(host[i])
	}
	out = append(out, cur)
	return out
}

// HNGIsSafe 便捷判定。
func HNGIsSafe(addr string) bool {
	return len(HNGEvaluate(addr, DefaultHNGPolicy())) == 0
}
