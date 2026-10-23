package main

// cookieprefixguard.go —— Set-Cookie 前缀语义（__Host- / __Secure-）与属性注入守卫。
//
// 背景：
//   启动器内嵌的登录 / 皮肤站 / 自建 BMCSAPI 流程可能透传或暂存服务器下发的 Cookie。
//   Cookie 名前缀是浏览器强制的安全契约：
//     __HOST-   必须 Secure、必须 Path=/、必须无 Domain、必须不被主机压制（host-only）；
//     __SECURE- 必须 Secure（HTTPS 下发）。
//   若服务端（或中间人在被降级的连接上）给一个名字带前缀、却不满足约束的 Cookie，说明其
//   前缀承诺是伪造的，接受它会让上层误以为该 Cookie 具备对应保护。此外 Set-Cookie 头里
//   出现裸 \r\n 可注入第二个 Cookie 或额外响应头（HTTP response splitting）。
//
// 本模块为纯字符串处理，不使用正则，用于在"接受 / 转发 / 落盘一个 Cookie"前校验。

const (
	CPReasonCRLF             = "cp-cookie-header-line-injection"
	CPReasonHostNotSecure    = "cp-host-prefix-requires-secure"
	CPReasonHostBadPath      = "cp-host-prefix-requires-path-eq-slash"
	CPReasonHostHasDomain    = "cp-host-prefix-forbids-domain"
	CPReasonSecureNotSecure  = "cp-secure-prefix-requires-secure"
	CPReasonBadSameSite      = "cp-invalid-samesite-value"
	CPReasonSameSiteNoneHTTP = "cp-samesite-none-requires-secure"
	CPReasonEmptyName        = "cp-empty-cookie-name"
	CPReasonControlChar      = "cp-control-character"
)

// 名称前缀（大小写不敏感比较时用小写副本）。
const cpHostPrefix = "__host-"
const cpSecurePrefix = "__secure-"

// CPPolicy 控制 Cookie 校验严格度。
type CPPolicy struct {
	EnforcePrefixes    bool // 强制 __Host-/__Secure- 语义
	RequireGoodSameSite bool // SameSite 取值必须合法
	SameSiteNoneSecure bool // SameSite=None 必须搭配 Secure
	BlockCRLF          bool
}

// CPFinding 记录一处 Cookie 风险。
type CPFinding struct {
	Reason string
	Name   string
	Detail string
}

// CPCookie 是一个待校验 Cookie 的解析视图。
type CPCookie struct {
	Name     string
	Secure   bool
	Path     string
	HasDomain bool
	Domain   string
	SameSite string // 原始 SameSite 值（未归一时）
}

// DefaultCPPolicy 返回默认严格策略。
func DefaultCPPolicy() CPPolicy {
	return CPPolicy{
		EnforcePrefixes:     true,
		RequireGoodSameSite: true,
		SameSiteNoneSecure:  true,
		BlockCRLF:           true,
	}
}

// cpLowerASCII 归一小写。
func cpLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// cpHasPrefixFold 大小写不敏感前缀判断。
func cpHasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if cpLowerASCII(s[i]) != prefix[i] {
			return false
		}
	}
	return true
}

// cpTrimSpace 去除首尾 ASCII 空白与制表符。
func cpTrimSpace(s string) string {
	start, end := 0, len(s)
	for start < end {
		c := s[start]
		if c == ' ' || c == '\t' {
			start++
			continue
		}
		break
	}
	for end > start {
		c := s[end-1]
		if c == ' ' || c == '\t' {
			end--
			continue
		}
		break
	}
	return s[start:end]
}

// cpHasControlByte 检测 CR/LF/NUL 等可断行字符。
func cpHasControlByte(s string) (bool, string) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\n', '\r':
			return true, CPReasonCRLF
		case 0:
			return true, CPReasonControlChar
		}
		if c < 0x20 && c != '\t' {
			return true, CPReasonControlChar
		}
	}
	return false, ""
}

// CPValidateRawSetCookie 直接校验一整条 Set-Cookie 头原始文本（含属性）。
func CPValidateRawSetCookie(raw string, pol CPPolicy) []CPFinding {
	var out []CPFinding
	if bad, reason := cpHasControlByte(raw); bad && pol.BlockCRLF {
		out = append(out, CPFinding{Reason: reason, Detail: "raw-set-cookie"})
	}
	parsed, perr := cpParseSetCookie(raw)
	if perr != "" {
		out = append(out, CPFinding{Reason: perr})
		return out
	}
	out = append(out, CPValidateCookie(parsed, pol)...)
	return out
}

// cpParseSetCookie 把 "name=value; Path=/; Secure; SameSite=..." 解析成 CPCookie。
func cpParseSetCookie(raw string) (CPCookie, string) {
	var c CPCookie
	// 首个段是 name=value。
	firstEnd := len(raw)
	for i := 0; i < len(raw); i++ {
		if raw[i] == ';' {
			firstEnd = i
			break
		}
	}
	first := raw[:firstEnd]
	eq := -1
	for i := 0; i < len(first); i++ {
		if first[i] == '=' {
			eq = i
			break
		}
	}
	if eq < 0 {
		return c, CPReasonEmptyName
	}
	c.Name = cpTrimSpace(first[:eq])
	if c.Name == "" {
		return c, CPReasonEmptyName
	}

	rest := raw[firstEnd:]
	// 逐属性解析。
	i := 0
	for i < len(rest) {
		if rest[i] == ';' {
			i++
			continue
		}
		j := i
		for j < len(rest) && rest[j] != ';' {
			j++
		}
		part := cpTrimSpace(rest[i:j])
		i = j
		if part == "" {
			continue
		}
		key := part
		val := ""
		if pe := cpIndexByte(part, '='); pe >= 0 {
			key = cpTrimSpace(part[:pe])
			val = cpTrimSpace(part[pe+1:])
		}
		keyLow := cpToLower(key)
		switch keyLow {
		case "secure":
			c.Secure = true
		case "path":
			c.Path = val
		case "domain":
			c.HasDomain = true
			c.Domain = val
		case "samesite":
			c.SameSite = val
		}
	}
	return c, ""
}

// cpIndexByte 是 strings.IndexByte 的本模块版本。
func cpIndexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// cpToLower 返回 ASCII 小写副本。
func cpToLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = cpLowerASCII(s[i])
	}
	return string(b)
}

// CPValidateCookie 校验已解析 Cookie 是否满足其名称前缀承诺与 SameSite 约束。
func CPValidateCookie(c CPCookie, pol CPPolicy) []CPFinding {
	var out []CPFinding
	if c.Name == "" {
		return []CPFinding{{Reason: CPReasonEmptyName}}
	}
	if pol.EnforcePrefixes {
		if cpHasPrefixFold(c.Name, cpHostPrefix) {
			if !c.Secure {
				out = append(out, CPFinding{Reason: CPReasonHostNotSecure, Name: c.Name})
			}
			if c.Path != "/" {
				out = append(out, CPFinding{Reason: CPReasonHostBadPath, Name: c.Name, Detail: c.Path})
			}
			if c.HasDomain {
				out = append(out, CPFinding{Reason: CPReasonHostHasDomain, Name: c.Name, Detail: c.Domain})
			}
		} else if cpHasPrefixFold(c.Name, cpSecurePrefix) {
			if !c.Secure {
				out = append(out, CPFinding{Reason: CPReasonSecureNotSecure, Name: c.Name})
			}
		}
	}
	if pol.RequireGoodSameSite && c.SameSite != "" {
		switch cpToLower(c.SameSite) {
		case "strict", "lax", "none":
		default:
			out = append(out, CPFinding{Reason: CPReasonBadSameSite, Name: c.Name, Detail: c.SameSite})
		}
	}
	if pol.SameSiteNoneSecure && cpToLower(c.SameSite) == "none" && !c.Secure {
		out = append(out, CPFinding{Reason: CPReasonSameSiteNoneHTTP, Name: c.Name})
	}
	return out
}

// CPIsSafe 便捷判定。
func CPIsSafe(raw string) bool {
	return len(CPValidateRawSetCookie(raw, DefaultCPPolicy())) == 0
}
