package main

// certnameguard.go —— TLS 服务器证书主机名/SAN/通配匹配规则守卫。
//
// 背景：
//   即便证书链验证通过，若"证书名字 ↔ 连接主机名"匹配实现过宽，仍会连到冒用证书的主机：
//     - 通配只允许在最左标签（*.example.com），不接受 a.*.com、*com、good*.com（部分通配）；
//     - 通配只匹配单层标签，不跨点（*.example.com 不匹配 a.b.example.com）；
//     - 不能用裸后缀/包含子串匹配（example.com 不能匹配 notexample.com）；
//     - 内网/裸 IP 必须命中 IP SAN，不能拿 DNS 名去对 IP；
//     - 主机名尾点（FQDN 点）需归一后比较。
//   纯字符串标签匹配，不做密码学校验，不使用正则。

const (
	CNReasonNoNameMatched     = "cert-no-san-or-cn-matches-server-name"
	CNReasonPartialWildcard   = "cert-wildcard-is-partial-label"
	CNReasonWildcardAcrossDot = "cert-wildcard-matches-across-label-boundary"
	CNReasonBareSuffixMatch   = "cert-name-matched-by-bare-suffix-substring"
	CNReasonIPWithoutIPSAN    = "cert-ip-server-without-ip-san"
)

// CNFinding 记录一处证书名匹配问题。
type CNFinding struct {
	Reason string
}

// CNMatchName 判断证书上的一个标识（DNS SAN 或 CN）是否匹配连接主机名。
// 返回 (matched, validRule)：validRule=false 表示该证书标识本身是非法通配规则。
func CNMatchName(ident, serverName string) (matched bool, validRule bool) {
	id := cnLower(cnTrimDot(ident))
	name := cnLower(cnTrimDot(serverName))
	if id == "" || name == "" {
		return false, false
	}
	star := cnIndexByte(id, '*')
	if star < 0 {
		// 精确名，必须整串相等（不允许子串）
		return id == name, true
	}
	// 含通配：只允许恰好为 "*" 且位于最左标签
	if star != 0 || id[0] != '*' {
		return false, false
	}
	rest := id[1:] // 期望以 '.' 开头，如 ".example.com"
	if rest == "" || rest[0] != '.' {
		return false, false // *com 这类
	}
	// 不能再有第二个 *（部分/多层通配）
	if cnIndexByte(rest, '*') >= 0 {
		return false, false
	}
	suffix := rest // ".example.com"
	if !cnHasSuffix(name, suffix) {
		return false, true
	}
	prefix := name[:len(name)-len(suffix)]
	// 通配替代的前缀必须非空且不含点（不跨标签）
	if prefix == "" || cnIndexByte(prefix, '.') >= 0 {
		return false, true
	}
	return true, true
}

// CNEvaluate 对证书全部标识评估是否能安全匹配 serverName。
// serverIsIP=true 时要求证书提供 IP SAN（由调用方在 ipSANs 中给出精确 IP）。
func CNEvaluate(dnsNames []string, ipSANs []string, serverName string,
	serverIsIP bool) (safe bool, findings []CNFinding) {
	if serverIsIP {
		for _, ip := range ipSANs {
			if ip == serverName {
				return true, nil
			}
		}
		findings = append(findings, CNFinding{Reason: CNReasonIPWithoutIPSAN})
		return false, findings
	}

	matched := false
	for _, ident := range dnsNames {
		ok, valid := CNMatchName(ident, serverName)
		if !valid {
			if ident != "" && cnIndexByte(ident, '*') >= 0 {
				findings = append(findings, CNFinding{Reason: CNReasonPartialWildcard})
			}
			continue
		}
		if ok {
			matched = true
		}
	}
	if !matched && len(findings) == 0 {
		findings = append(findings, CNFinding{Reason: CNReasonNoNameMatched})
	}
	return matched && len(findings) == 0, findings
}

func cnLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func cnTrimDot(s string) string {
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}

func cnIndexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func cnHasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

// CNHasReason 判定结果含某类问题。
func CNHasReason(findings []CNFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
