package main

// ipliteralguard.go —— 主机位上的"替代 IP 编码"归一化，防止绕过 SSRF/私网过滤。
//
// 背景：
//   只对标准点分十进制（127.0.0.1）做私网判断会被各种等价写法绕过，连接最终仍落到环回/内网：
//     - 十进制整数：http://2130706433/  == 127.0.0.1
//     - 八进制：http://0177.0.0.1/
//     - 十六进制：http://0x7f.0.0.1/ 、 http://0x7f000001/
//     - 混合进制：http://0177.0.1/
//     - IPv6 环回 ::1；IPv4 映射 ::ffff:127.0.0.1；IPv4 兼容 ::127.0.0.1
//     - 括号 IPv6 [::1]、省略前导零 0177.0.0.1
//   本模块把主机位字符串归一为 4 段 IPv4（若可映射）或识别 IPv6 环回/映射，再交 HSClassifyIP4 分类。
//   纯手写解析，不使用正则、不做真实 DNS。

const (
	ILReasonAmbiguousEncoding = "ip-literal-non-canonical-encoding"
	ILReasonIPv6Loopback      = "ip-literal-ipv6-loopback"
	ILReasonIPv6MappedPrivate = "ip-literal-ipv6-mapped-ipv4-private"
)

// ILResult 归一化结果。
type ILResult struct {
	IsIP       bool
	Canonical4 string // 归一后的点分 IPv4（空表示非 IPv4 可表达）
	Class      HSIPClass
	Reasons    []string
}

// ILNormalizeHost 解析主机位（已去端口、去方括号由调用方处理也可传带括号）。
func ILNormalizeHost(host string) ILResult {
	h := host
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}

	// IPv6：含冒号
	if ilContainsColon(h) {
		return ilClassifyV6(h)
	}

	// 纯 IPv4 点分（允许每段十进制/0x 十六进制/0 开头八进制）或单个整数
	parts := ilSplitDots(h)
	if len(parts) == 0 {
		return ILResult{}
	}
	nums := make([]int64, 0, 4)
	nonCanonical := false
	for _, seg := range parts {
		v, ok, nc := ilParseSegment(seg)
		if !ok {
			return ILResult{}
		}
		if nc {
			nonCanonical = true
		}
		nums = append(nums, v)
	}

	var b [4]int64
	ok := false
	switch len(nums) {
	case 1:
		v := nums[0]
		if v < 0 || v > 0xffffffff {
			return ILResult{}
		}
		b[0], b[1], b[2], b[3] = (v>>24)&255, (v>>16)&255, (v>>8)&255, v&255
		ok = true
		if h != ilCanon(b) {
			nonCanonical = true
		}
	case 2:
		if nums[0] > 255 || nums[1] > 0xffffff {
			return ILResult{}
		}
		b[0] = nums[0]
		b[1], b[2], b[3] = (nums[1]>>16)&255, (nums[1]>>8)&255, nums[1]&255
		ok = true
	case 3:
		if nums[0] > 255 || nums[1] > 255 || nums[2] > 0xffff {
			return ILResult{}
		}
		b[0], b[1] = nums[0], nums[1]
		b[2], b[3] = (nums[2]>>8)&255, nums[2]&255
		ok = true
	case 4:
		for _, v := range nums {
			if v > 255 {
				return ILResult{}
			}
		}
		b[0], b[1], b[2], b[3] = nums[0], nums[1], nums[2], nums[3]
		ok = true
	}
	if !ok {
		return ILResult{}
	}
	canon := ilCanon(b)
	res := ILResult{IsIP: true, Canonical4: canon,
		Class: HSClassifyIP4(canon)}
	if nonCanonical || h != canon {
		res.Reasons = append(res.Reasons, ILReasonAmbiguousEncoding)
	}
	return res
}

// ilParseSegment 解析一段：十进制 / 0x 十六进制 / 前导 0 八进制。
func ilParseSegment(s string) (val int64, ok bool, nonCanonical bool) {
	if s == "" {
		return 0, false, false
	}
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		v := ilParseRadix(s[2:], 16)
		if v < 0 {
			return 0, false, false
		}
		return v, true, true
	}
	if len(s) >= 2 && s[0] == '0' {
		if v := ilParseRadix(s, 8); v >= 0 {
			// 前导 0 八进制（如 0177）
			return v, true, true
		}
	}
	v := ilParseRadix(s, 10)
	if v < 0 {
		return 0, false, false
	}
	return v, true, false
}

func ilParseRadix(s string, base int) int64 {
	if s == "" {
		return -1
	}
	var v int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		d := -1
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case base == 16 && c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case base == 16 && c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		}
		if d < 0 || d >= base {
			return -1
		}
		v = v*int64(base) + int64(d)
		if v > 0xffffffff {
			return -1
		}
	}
	return v
}

func ilClassifyV6(h string) ILResult {
	// 去掉 IPv4 映射后缀 ::ffff:a.b.c.d / ::a.b.c.d，复用 IPv4 判定
	lower := ilLower(h)
	const mapPrefix = "::ffff:"
	const compatPrefix = "::"
	if ilHasPrefix(lower, mapPrefix) {
		tail := h[len(mapPrefix):]
		if r := ILNormalizeHost(tail); r.IsIP {
			r.Reasons = append(r.Reasons, ILReasonIPv6MappedPrivate)
			return r
		}
	}
	// ::127.0.0.1 形式的 IPv4 兼容
	if ilHasPrefix(lower, compatPrefix) && ilContainsDot(h[2:]) {
		tail := h[2:]
		if r := ILNormalizeHost(tail); r.IsIP {
			return r
		}
	}
	if ilIsLoopbackV6(lower) {
		return ILResult{IsIP: true, Class: HSIPLoopback,
			Reasons: []string{ILReasonIPv6Loopback}}
	}
	// 其它 IPv6 不在此模块展开（公网 v6 默认放行，由调用方按需扩展）
	return ILResult{IsIP: true, Class: HSIPPublic}
}

func ilIsLoopbackV6(lower string) bool {
	// 接受 ::1、0:0:0:0:0:0:0:1 及其前导零写法
	if lower == "::1" {
		return true
	}
	groups := ilSplitColon(lower)
	// 非简写全写：8 组，前 7 组为 0，末组为 1
	if len(groups) == 8 {
		for i := 0; i < 7; i++ {
			if groups[i] != "0" && groups[i] != "" {
				return false
			}
		}
		return groups[7] == "1"
	}
	return false
}

func ilCanon(b [4]int64) string {
	return ilItoa(b[0]) + "." + ilItoa(b[1]) + "." + ilItoa(b[2]) + "." + ilItoa(b[3])
}

func ilSplitDots(s string) []string {
	var out []string
	cur := ""
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, cur)
			cur = ""
			if i == len(s) {
				break
			}
			continue
		}
		cur += string(s[i])
	}
	if len(out) == 1 && out[0] == "" {
		return nil
	}
	return out
}

func ilSplitColon(s string) []string {
	var out []string
	cur := ""
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ':' {
			out = append(out, cur)
			cur = ""
			if i == len(s) {
				break
			}
			continue
		}
		cur += string(s[i])
	}
	return out
}

func ilContainsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

func ilContainsDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

func ilHasPrefix(s, pre string) bool {
	return len(s) >= len(pre) && s[:len(pre)] == pre
}

func ilHasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

func ilLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func ilItoa(i int64) string {
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

// ILHasReason 判定结果含某类问题。
func ILHasReason(r ILResult, reason string) bool {
	for _, x := range r.Reasons {
		if x == reason {
			return true
		}
	}
	return false
}
