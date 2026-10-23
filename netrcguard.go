package main

// netrcguard.go —— .netrc 风格机器凭据条目的解析与最小权限 / 明文落盘风险守卫。
//
// 背景：
//   部分下载 / 源配置流程（或其依赖的工具，如 curl、git over http）会读取 ~/.netrc 获取
//   "machine X login Y password Z"。风险：
//     1. 明文密码 / 令牌长期落盘，且默认权限可能被同机其它账户读取；
//     2. "default" 条目会把凭据发给任意未命中的主机，造成凭据向第三方源 / 攻击者主机泄露；
//     3. 同一台机器配置多条 machine，下载到陌生主机时误送凭据；
//     4. 令牌被写进日志 / 错误信息；
//     5. 过宽的 machine 匹配（以 IP 地址、裸顶级名登记）。
//
// 本模块做纯字符解析（不依赖外部 netrc 库），并对"将要写入 / 读取的 netrc"做策略裁决。

const (
	NRCReasonDefaultMachine   = "nrc-default-machine-leaks-to-any-host"
	NRCReasonDuplicateMachine = "nrc-duplicate-machine-entry"
	NRCReasonEmptyPassword    = "nrc-empty-password"
	NRCReasonWeakPassword     = "nrc-weak-or-placeholder-secret"
	NRCReasonMachineIsIP      = "nrc-machine-keyed-by-raw-ip"
	NRCReasonMachineTooBroad  = "nrc-machine-name-too-broad"
	NRCReasonMalformed        = "nrc-malformed-token-sequence"
	NRCReasonUnsafeFileMode   = "nrc-netrc-file-mode-too-open"
)

// NRCPolicy 控制 netrc 校验严格度。
type NRCPolicy struct {
	ForbidDefaultMachine bool
	ForbidDuplicates     bool
	RequireSecretLength  int
	ForbidRawIPMachine   bool
	MaxSafeFileMode      uint32
}

// NRCEntry 是一条 machine/default 凭据。
type NRCEntry struct {
	Machine  string // "default" 表示默认条目
	Login    string
	Password string
	IsDefault bool
}

// NRCFinding 记录一处风险。
type NRCFinding struct {
	Reason  string
	Machine string
	Detail  string
}

// DefaultNRCPolicy 返回默认严格策略。
func DefaultNRCPolicy() NRCPolicy {
	return NRCPolicy{
		ForbidDefaultMachine: true,
		ForbidDuplicates:     true,
		RequireSecretLength:  12,
		ForbidRawIPMachine:   true,
		MaxSafeFileMode:      0o600,
	}
}

// nrcTokenize 按空白切词（不做引号展开，netrc 标准允许空格在引号内；这里保守识别）。
func nrcTokenize(line string) []string {
	tokens := []string{}
	cur := ""
	inQuote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			} else {
				cur += string(c)
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = c
			continue
		}
		if c == ' ' || c == '\t' {
			if cur != "" {
				tokens = append(tokens, cur)
				cur = ""
			}
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		tokens = append(tokens, cur)
	}
	return tokens
}

// NRCParse 解析 netrc 文本（支持多行，machine/default/login/password/account/macdef）。
func NRCParse(text string) ([]NRCEntry, []string) {
	entries := []NRCEntry{}
	errors := []string{}
	var cur *NRCEntry
	flush := func() {
		if cur != nil {
			entries = append(entries, *cur)
			cur = nil
		}
	}

	lines := nrcSplitLines(text)
	for _, line := range lines {
		// 去掉行注释（# 开头，允许前导空白）。
		trimmed := nrcTrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		toks := nrcTokenize(line)
		i := 0
		for i < len(toks) {
			kw := toks[i]
			switch kw {
			case "machine", "default":
				flush()
				cur = &NRCEntry{}
				if kw == "default" {
					cur.IsDefault = true
					cur.Machine = "default"
					i++
					continue
				}
				if i+1 >= len(toks) {
					errors = append(errors, NRCReasonMalformed)
					i++
					continue
				}
				cur.Machine = toks[i+1]
				i += 2
			case "login":
				if cur == nil || i+1 >= len(toks) {
					errors = append(errors, NRCReasonMalformed)
					i++
					continue
				}
				cur.Login = toks[i+1]
				i += 2
			case "password", "account":
				if cur == nil || i+1 >= len(toks) {
					errors = append(errors, NRCReasonMalformed)
					i++
					continue
				}
				cur.Password = toks[i+1]
				i += 2
			default:
				// 未知 token（如 macdef 内容）跳过。
				i++
			}
		}
	}
	flush()
	return entries, errors
}

// nrcSplitLines 按 \n（兼容 \r\n）切行。
func nrcSplitLines(s string) []string {
	out := []string{}
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		if s[i] == '\r' {
			continue
		}
		cur += string(s[i])
	}
	out = append(out, cur)
	return out
}

func nrcTrimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}

// nrcPlaceholderSecrets 为明显占位 / 弱口令。
var nrcPlaceholderSecrets = map[string]bool{
	"password": true, "123456": true, "changeme": true, "secret": true,
	"admin": true, "token": true, "your_password": true, "xxx": true,
}

// NRCEvaluate 校验解析出的 netrc 条目集合。
func NRCEvaluate(entries []NRCEntry, parseErrors []string, fileMode uint32, pol NRCPolicy) []NRCFinding {
	var out []NRCFinding
	add := func(reason, machine, detail string) {
		out = append(out, NRCFinding{Reason: reason, Machine: machine, Detail: detail})
	}
	for _, e := range parseErrors {
		add(e, "", "")
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDefault {
			if pol.ForbidDefaultMachine {
				add(NRCReasonDefaultMachine, "default", "")
			}
			continue
		}
		if pol.ForbidDuplicates {
			if seen[e.Machine] {
				add(NRCReasonDuplicateMachine, e.Machine, "")
			}
			seen[e.Machine] = true
		}
		if e.Password == "" {
			add(NRCReasonEmptyPassword, e.Machine, "")
		} else {
			if len(e.Password) < pol.RequireSecretLength {
				add(NRCReasonWeakPassword, e.Machine, "too-short")
			} else if nrcPlaceholderSecrets[nrcToLower(e.Password)] {
				add(NRCReasonWeakPassword, e.Machine, "placeholder")
			}
		}
		if pol.ForbidRawIPMachine && nrcLooksRawIP(e.Machine) {
			add(NRCReasonMachineIsIP, e.Machine, "")
		}
		if nrcMachineTooBroad(e.Machine) {
			add(NRCReasonMachineTooBroad, e.Machine, "")
		}
	}
	if fileMode != 0 && fileMode&0o777&^pol.MaxSafeFileMode != 0 {
		add(NRCReasonUnsafeFileMode, "", nrcItoaMode(fileMode))
	}
	return out
}

// nrcLooksRawIP 判断机器名是否为裸 IPv4。
func nrcLooksRawIP(m string) bool {
	_, ok := drgParseIPv4(m)
	return ok
}

// nrcMachineTooBroad 判断机器名是否过宽（单标签 / 裸顶级）。localhost 等环回名豁免。
func nrcMachineTooBroad(m string) bool {
	if m == "" {
		return true
	}
	low := nrcToLower(m)
	if low == "localhost" || low == "localhost.localdomain" || low == "ip6-localhost" {
		return false
	}
	hasDot := false
	for i := 0; i < len(m); i++ {
		if m[i] == '.' {
			hasDot = true
		}
	}
	return !hasDot
}

func nrcToLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func nrcItoaMode(m uint32) string {
	if m == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for m > 0 {
		i--
		b[i] = byte('0' + m%10)
		m /= 10
	}
	return string(b[i:])
}

// NRCScanText 一步解析 + 校验（fileMode 传 0 表示不检查文件权限位）。
func NRCScanText(text string, fileMode uint32) []NRCFinding {
	pol := DefaultNRCPolicy()
	entries, errs := NRCParse(text)
	return NRCEvaluate(entries, errs, fileMode, pol)
}
