package main

// dnsrebindingguard.go —— DNS 重绑定（Rebinding）与"先校验后连接"解析一致性守卫。
//
// 背景：
//   启动器会按主机名访问 Mojang / 第三方下载 / 自建 BMCSAPI 等服务。典型的 SSRF 防线是
//   在发起连接前把主机名解析成 IP，判定其不是环回 / 私网 / 链路本地地址。但 DNS 记录的
//   TTL 可以被权威服务器设成 0（或极小），并在两次查询之间切换应答：第一次返回公网 IP
//   通过安全检查，真正建立连接时第二次解析返回 127.0.0.1 / 169.254.169.254 / 10.x，于是
//   校验被绕过，请求被打到内网服务。这就是 DNS rebinding。
//
// 本模块是纯逻辑内核，不真正发 DNS 查询；它负责：
//   1. 校验单次应答的 TTL 与地址集合（拒绝 0 TTL、公私网混合、环回 / 链路本地 / 元数据）；
//   2. 比较"安全检查时的解析结果"与"连接前再次解析的结果"，地址集合不一致即判重绑定；
//   3. 提供 IPv4 / IPv6（环回 / 唯一本地 fc00::/7 / 链路本地 fe80:: / ULA）纯字符分类。
//
// 不使用正则。

const (
	DRGReasonZeroTTL          = "drg-zero-ttl"
	DRGReasonTTLTooSmall      = "drg-ttl-too-small"
	DRGReasonNoAddresses      = "drg-no-addresses"
	DRGReasonLoopback         = "drg-loopback-address"
	DRGReasonPrivate          = "drg-private-address"
	DRGReasonLinkLocal        = "drg-link-local-address"
	DRGReasonMetadata         = "drg-cloud-metadata-address"
	DRGReasonMixedTrust       = "drg-mixed-public-private-answers"
	DRGReasonInconsistent     = "drg-resolution-changed-between-check-and-connect"
	DRGReasonBadIPLiteral     = "drg-bad-ip-literal"
	DRGReasonAddressFamilies  = "drg-mixed-ipv4-ipv6"
)

// DRGPolicy 控制 DNS 重绑定防护严格度。
type DRGPolicy struct {
	MinTTLSeconds         int  // 允许的最小 TTL
	ForbidZeroTTL         bool // 显式拒绝 0 TTL
	ForbidMixedTrust      bool // 拒绝同一应答里公私网地址混合
	RequireConsistent     bool // 连接前复解析必须与校验时一致
	ForbidMixedFamilies   bool // 拒绝同一应答里 IPv4/IPv6 混排（便于固定解析面）
}

// DRGFinding 记录一处解析风险。
type DRGFinding struct {
	Reason string
	Host   string
	Detail string
}

// DefaultDRGPolicy 返回面向"按主机名访问不可信端点"的默认严格策略。
func DefaultDRGPolicy() DRGPolicy {
	return DRGPolicy{
		MinTTLSeconds:       30,
		ForbidZeroTTL:       true,
		ForbidMixedTrust:    true,
		RequireConsistent:   true,
		ForbidMixedFamilies: false,
	}
}

// drgIsDigit / drgIsHexDigit 为纯字符判定。
func drgIsDigit(b byte) bool { return b >= '0' && b <= '9' }
func drgIsHexDigit(b byte) bool {
	return drgIsDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// drgParseIPv4 解析点分十进制 IPv4，失败返回 false。
func drgParseIPv4(s string) ([4]byte, bool) {
	var ip [4]byte
	parts := 0
	start := 0
	for i := 0; i <= len(s); i++ {
		if i != len(s) && s[i] != '.' {
			continue
		}
		if parts == 4 {
			return ip, false
		}
		seg := s[start:i]
		if len(seg) == 0 || len(seg) > 3 {
			return ip, false
		}
		v := 0
		for k := 0; k < len(seg); k++ {
			if !drgIsDigit(seg[k]) {
				return ip, false
			}
			v = v*10 + int(seg[k]-'0')
		}
		if v > 255 {
			return ip, false
		}
		ip[parts] = byte(v)
		parts++
		start = i + 1
	}
	if parts != 4 {
		return ip, false
	}
	return ip, true
}

// drgExpandIPv6 把 RFC5952 形式的 IPv6 展开为 8 组 16 位值；支持 :: 压缩，不支持内嵌 IPv4。
func drgExpandIPv6(s string) ([8]uint16, bool) {
	var groups [8]uint16
	doubleColon := -1
	head := []uint16{}
	tail := []uint16{}
	inTail := false
	i := 0
	for i < len(s) {
		if s[i] == ':' {
			if i+1 < len(s) && s[i+1] == ':' {
				if doubleColon >= 0 {
					return groups, false // 多个 ::
				}
				doubleColon = len(head)
				inTail = true
				i += 2
				continue
			}
			return groups, false
		}
		j := i
		for j < len(s) && s[j] != ':' {
			j++
		}
		tok := s[i:j]
		if len(tok) == 0 || len(tok) > 4 {
			return groups, false
		}
		v := uint16(0)
		for k := 0; k < len(tok); k++ {
			if !drgIsHexDigit(tok[k]) {
				return groups, false
			}
			var d int
			c := tok[k]
			switch {
			case drgIsDigit(c):
				d = int(c - '0')
			case c >= 'a' && c <= 'f':
				d = int(c-'a') + 10
			default:
				d = int(c-'A') + 10
			}
			v = v*16 + uint16(d)
		}
		if inTail {
			tail = append(tail, v)
		} else {
			head = append(head, v)
		}
		i = j
		if i < len(s) && s[i] == ':' {
			i++
		}
	}
	explicit := len(head) + len(tail)
	if explicit > 8 {
		return groups, false
	}
	if doubleColon < 0 && explicit != 8 {
		return groups, false
	}
	all := []uint16{}
	all = append(all, head...)
	if doubleColon >= 0 {
		for k := 0; k < 8-explicit; k++ {
			all = append(all, 0)
		}
	}
	all = append(all, tail...)
	if len(all) != 8 {
		return groups, false
	}
	copy(groups[:], all)
	return groups, true
}

// DRGClass 表示地址可信级别。
type DRGClass int

const (
	DRGClassPublic DRGClass = iota
	DRGClassLoopback
	DRGClassPrivate
	DRGClassLinkLocal
	DRGClassMetadata
)

// drgClassifyIP 返回地址可信级别；非法字面量第二返回值为 false。
func drgClassifyIP(addr string) (DRGClass, bool) {
	if ip, ok := drgParseIPv4(addr); ok {
		a, b := ip[0], ip[1]
		switch {
		case a == 0 || a == 127:
			return DRGClassLoopback, true
		case a == 10:
			return DRGClassPrivate, true
		case a == 192 && b == 168:
			return DRGClassPrivate, true
		case a == 172 && b >= 16 && b <= 31:
			return DRGClassPrivate, true
		case a == 169 && b == 254:
			if ip[2] == 169 && ip[3] == 254 {
				return DRGClassMetadata, true
			}
			return DRGClassLinkLocal, true
		case a >= 224:
			return DRGClassLinkLocal, true // 组播 / 保留段统一不放行
		default:
			return DRGClassPublic, true
		}
	}
	g, ok := drgExpandIPv6(addr)
	if !ok {
		return DRGClassPublic, false
	}
	switch {
	case g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 &&
		g[4] == 0 && g[5] == 0 && g[6] == 0 && g[7] == 1:
		return DRGClassLoopback, true
	case g[0]&0xfe00 == 0xfc00:
		return DRGClassPrivate, true // fc00::/7 唯一本地地址
	case g[0]&0xffc0 == 0xfe80:
		return DRGClassLinkLocal, true // fe80::/10
	default:
		return DRGClassPublic, true
	}
}

// drgHasIPv4 / drgHasIPv6 判断应答里是否出现对应族。
func drgHasIPv4(addrs []string) bool {
	for _, a := range addrs {
		if _, ok := drgParseIPv4(a); ok {
			return true
		}
	}
	return false
}

// drgHasIPv6 判断应答里是否出现可解析的 IPv6 字面量。
func drgHasIPv6(addrs []string) bool {
	for _, a := range addrs {
		if _, ok := drgParseIPv4(a); ok {
			continue
		}
		if _, ok := drgExpandIPv6(a); ok {
			return true
		}
	}
	return false
}

// DRGEvaluateAnswer 校验单次 DNS 应答。
func DRGEvaluateAnswer(host string, addrs []string, ttlSeconds int, pol DRGPolicy) []DRGFinding {
	var out []DRGFinding
	if pol.ForbidZeroTTL && ttlSeconds == 0 {
		out = append(out, DRGFinding{Reason: DRGReasonZeroTTL, Host: host})
	}
	if pol.MinTTLSeconds > 0 && ttlSeconds > 0 && ttlSeconds < pol.MinTTLSeconds {
		out = append(out, DRGFinding{Reason: DRGReasonTTLTooSmall, Host: host, Detail: itoaDRG(ttlSeconds)})
	}
	if len(addrs) == 0 {
		out = append(out, DRGFinding{Reason: DRGReasonNoAddresses, Host: host})
		return out
	}
	if pol.ForbidMixedFamilies && drgHasIPv4(addrs) && drgHasIPv6(addrs) {
		out = append(out, DRGFinding{Reason: DRGReasonAddressFamilies, Host: host})
	}
	sawPublic := false
	sawPrivate := false
	for _, a := range addrs {
		cls, ok := drgClassifyIP(a)
		if !ok {
			out = append(out, DRGFinding{Reason: DRGReasonBadIPLiteral, Host: host, Detail: a})
			continue
		}
		switch cls {
		case DRGClassLoopback:
			out = append(out, DRGFinding{Reason: DRGReasonLoopback, Host: host, Detail: a})
			sawPrivate = true
		case DRGClassPrivate:
			out = append(out, DRGFinding{Reason: DRGReasonPrivate, Host: host, Detail: a})
			sawPrivate = true
		case DRGClassLinkLocal:
			out = append(out, DRGFinding{Reason: DRGReasonLinkLocal, Host: host, Detail: a})
			sawPrivate = true
		case DRGClassMetadata:
			out = append(out, DRGFinding{Reason: DRGReasonMetadata, Host: host, Detail: a})
			sawPrivate = true
		case DRGClassPublic:
			sawPublic = true
		}
	}
	if pol.ForbidMixedTrust && sawPublic && sawPrivate {
		out = append(out, DRGFinding{Reason: DRGReasonMixedTrust, Host: host})
	}
	return out
}

// drgAddressSet 把地址列表归一成集合（排序不必要，map 即可）。
func drgAddressSet(addrs []string) map[string]bool {
	m := map[string]bool{}
	for _, a := range addrs {
		m[a] = true
	}
	return m
}

// DRGCompareResolutions 比较校验时与连接前的地址集合是否一致。
func DRGCompareResolutions(host string, checked, connect []string, pol DRGPolicy) []DRGFinding {
	if !pol.RequireConsistent {
		return nil
	}
	cs := drgAddressSet(checked)
	ns := drgAddressSet(connect)
	changed := false
	for a := range ns {
		if !cs[a] {
			changed = true
			break
		}
	}
	if !changed {
		for a := range cs {
			if !ns[a] {
				changed = true
				break
			}
		}
	}
	if changed {
		return []DRGFinding{{Reason: DRGReasonInconsistent, Host: host}}
	}
	return nil
}

// itoaDRG 是本模块自用的简易整数转字符串，避免引入 strconv 造成的命名顾虑。
func itoaDRG(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// DRGIsSafe 便捷判定：应答可信且无重绑定迹象。
func DRGIsSafe(host string, addrs []string, ttl int) bool {
	pol := DefaultDRGPolicy()
	return len(DRGEvaluateAnswer(host, addrs, ttl, pol)) == 0
}
