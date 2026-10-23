package main

// iniparseguard.go —— INI 配置解析的注入与歧义守卫。
//
// 背景：
//   启动器读取 Java 安装配置、服务端配置等 INI 文件。风险：
//     - 段名/键值里裸 CRLF 伪造新行；
//     - 未闭合的段括号 [section；同一键在同段重复（取首/取尾分歧）；
//     - 段名嵌套或含控制字符；值里出现行内换行转义被旧解析器接受；
//     - 键值分隔符缺失（无 = 的赋值行被静默忽略，导致安全配置未生效）；
//     - BOM 残留在首段名前造成段名不匹配；
//     - 值以引号包裹但引号不配对。
//   纯字符逐行解析，不使用正则。

const (
	INIReasonUnclosedSection  = "ini-section-header-bracket-not-closed"
	INIReasonDuplicateKey     = "ini-duplicate-key-in-same-section-ambiguous"
	INIReasonMissingEquals    = "ini-assignment-line-missing-equals-separator"
	INIReasonBareControl      = "ini-key-or-value-contains-bare-control-character"
	INIReasonBOM              = "ini-file-starts-with-utf8-bom"
	INIReasonUnbalancedQuote  = "ini-value-quotes-not-balanced"
	INIReasonEmptySectionName = "ini-section-name-empty"
)

// INIFinding 记录一处问题。
type INIFinding struct {
	Reason string
	Line   int
	Detail string
}

// INIEntry 是一个键值（含所属段）。
type INIEntry struct {
	Section string
	Key     string
	Value   string
	Line    int
}

// INIResult 解析结果。
type INIResult struct {
	Entries  []INIEntry
	Findings []INIFinding
}

// INIParse 解析 INI 文本。
func INIParse(text string) INIResult {
	res := INIResult{}
	if len(text) >= 3 && text[0] == 0xef && text[1] == 0xbb && text[2] == 0xbf {
		res.Findings = append(res.Findings, INIFinding{Reason: INIReasonBOM, Line: 1})
		text = text[3:]
	}
	section := ""
	line := 1
	type sk struct{ s, k string }
	seen := map[sk]int{}
	n := len(text)
	i := 0
	for i <= n {
		// 取一行
		j := i
		for j < n && text[j] != '\n' {
			j++
		}
		raw := text[i:j]
		// 去行尾 CR
		if len(raw) > 0 && raw[len(raw)-1] == '\r' {
			raw = raw[:len(raw)-1]
		}
		trimmed := iniTrim(raw)

		if trimmed != "" && trimmed[0] != ';' && trimmed[0] != '#' {
			if trimmed[0] == '[' {
				if trimmed[len(trimmed)-1] != ']' {
					res.Findings = append(res.Findings, INIFinding{Reason: INIReasonUnclosedSection, Line: line})
				} else {
					name := trimmed[1 : len(trimmed)-1]
					if iniTrim(name) == "" {
						res.Findings = append(res.Findings, INIFinding{Reason: INIReasonEmptySectionName, Line: line})
					}
					section = iniTrim(name)
				}
			} else if eq := iniIndexByte(trimmed, '='); eq >= 0 {
				key := iniTrim(trimmed[:eq])
				val := trimmed[eq+1:]
				if iniHasControl(key) {
					res.Findings = append(res.Findings, INIFinding{Reason: INIReasonBareControl, Line: line, Detail: "key"})
				}
				unq, balanced := iniStripQuotes(val)
				if !balanced {
					res.Findings = append(res.Findings, INIFinding{Reason: INIReasonUnbalancedQuote, Line: line})
				}
				if iniHasControl(unq) {
					res.Findings = append(res.Findings, INIFinding{Reason: INIReasonBareControl, Line: line, Detail: "value"})
				}
				id := sk{section, key}
				if first, dup := seen[id]; dup {
					res.Findings = append(res.Findings, INIFinding{Reason: INIReasonDuplicateKey,
						Line: line, Detail: key + "@" + iniItoa(int64(first))})
				} else {
					seen[id] = line
				}
				res.Entries = append(res.Entries, INIEntry{Section: section, Key: key, Value: unq, Line: line})
			} else {
				res.Findings = append(res.Findings, INIFinding{Reason: INIReasonMissingEquals, Line: line,
					Detail: trimmed})
			}
		}

		if j >= n {
			break
		}
		i = j + 1
		line++
	}
	return res
}

func iniTrim(s string) string {
	a := 0
	b := len(s)
	for a < b && (s[a] == ' ' || s[a] == '\t') {
		a++
	}
	for b > a && (s[b-1] == ' ' || s[b-1] == '\t') {
		b--
	}
	return s[a:b]
}

func iniIndexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func iniHasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// iniStripQuotes 去除成对包裹的单/双引号；不配对时返回原文与 false。
func iniStripQuotes(s string) (string, bool) {
	t := iniTrim(s)
	if len(t) >= 2 {
		if t[0] == '"' {
			if t[len(t)-1] == '"' {
				return t[1 : len(t)-1], true
			}
			return s, false
		}
		if t[0] == '\'' {
			if t[len(t)-1] == '\'' {
				return t[1 : len(t)-1], true
			}
			return s, false
		}
	}
	return s, true
}

func iniItoa(i int64) string {
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

// INIHasReason 判定结果含某类问题。
func INIHasReason(res INIResult, reason string) bool {
	for _, f := range res.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
