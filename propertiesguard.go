package main

// propertiesguard.go —— Java .properties 配置解析的注入与歧义守卫。
//
// 背景：
//   启动器会读 launcher.properties、服务端 server.properties、安装器应答文件。properties 语法有
//   一批容易被利用的角落：
//     - 行尾反斜杠"续行"，可把下一行的恶意键拼进值；CRLF/孤立 CR 处理不一致导致不同解析器分歧；
//     - \uXXXX 转义，畸形（\u00、\uGGGG）时解析器行为不一，可塞入控制字符/NUL/换行者伪造新行；
//     - 键内空白、行首空白被静默吞掉，造成"看似注释其实生效"；
//     - 重复键：不同实现取第一或最后，导致审计与实际运行不一致；
//     - 值里出现 CR/LF（经转义或裸字符）可伪造配置行。
//   本模块逐字符模拟解析，产出告警；不使用正则。

const (
	PRReasonMalformedUnicode   = "properties-malformed-unicode-escape"
	PRReasonBareControlInValue = "properties-bare-crlf-or-control-in-value"
	PRReasonDuplicateKey       = "properties-duplicate-key-last-wins-ambiguity"
	PRReasonDanglingContinue   = "properties-backslash-continuation-at-eof"
	PRReasonStrayCR            = "properties-lone-carriage-return"
	PRReasonKeyWhitespace      = "properties-key-has-embedded-whitespace"
)

// PRFinding 记录一处 properties 问题。
type PRFinding struct {
	Reason string
	Line   int
	Detail string
}

// PREntry 是解析出的一个键值。
type PREntry struct {
	Key   string
	Value string
	Line  int
}

// PRParseResult 是解析结果。
type PRParseResult struct {
	Entries  []PREntry
	Findings []PRFinding
}

// PRParse 解析 properties 文本（字节级，模拟 Java Properties 的续行/转义但记录风险）。
func PRParse(text string) PRParseResult {
	res := PRParseResult{}
	seen := map[string]int{} // key -> 首次行
	n := len(text)
	i := 0
	line := 1

	for i < n {
		// 跳过行首空白
		for i < n && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		// 注释行
		if text[i] == '#' || text[i] == '!' {
			for i < n && text[i] != '\n' {
				if text[i] == '\r' {
					res.Findings = append(res.Findings, PRFinding{Reason: PRReasonStrayCR, Line: line})
				}
				i++
			}
			if i < n {
				i++ // 消费 \n
				line++
			}
			continue
		}
		if text[i] == '\n' {
			i++
			line++
			continue
		}
		if text[i] == '\r' {
			res.Findings = append(res.Findings, PRFinding{Reason: PRReasonStrayCR, Line: line})
			if i+1 < n && text[i+1] == '\n' {
				i += 2
			} else {
				i++
			}
			line++
			continue
		}

		startLine := line
		key, ni := prReadKey(text, i)
		i = ni
		// 分隔符
		for i < n && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
		if i < n && (text[i] == '=' || text[i] == ':') {
			i++
		}
		for i < n && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
		val, vi, vl, fs := prReadValue(text, i, line)
		res.Findings = append(res.Findings, fs...)
		i, line = vi, vl

		if prKeyHasSpace(key) {
			res.Findings = append(res.Findings, PRFinding{Reason: PRReasonKeyWhitespace,
				Line: startLine, Detail: key})
		}
		if first, dup := seen[key]; dup {
			res.Findings = append(res.Findings, PRFinding{Reason: PRReasonDuplicateKey,
				Line: startLine, Detail: key + "@" + prItoa(int64(first))})
		} else {
			seen[key] = startLine
		}
		res.Entries = append(res.Entries, PREntry{Key: key, Value: val, Line: startLine})
	}
	return res
}

// prReadKey 读取到分隔符或行尾前的键。键不跨行，不消费分隔符。
func prReadKey(text string, i int) (key string, ni int) {
	n := len(text)
	var buf []byte
	for i < n {
		c := text[i]
		if c == '=' || c == ':' || c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			break
		}
		if c == '\\' && i+1 < n {
			if text[i+1] == 'u' {
				ch, ok, adv := prReadUnicode(text, i)
				if !ok {
					buf = append(buf, '?')
				} else {
					buf = append(buf, ch...)
				}
				i += adv
				continue
			}
			buf = append(buf, prUnescape(text[i+1]))
			i += 2
			continue
		}
		buf = append(buf, c)
		i++
	}
	return string(buf), i
}

// prReadValue 读取值，处理转义与行尾续行，返回告警。
func prReadValue(text string, i int, startLine int) (val string, ni int, line int, fs []PRFinding) {
	n := len(text)
	line = startLine
	var buf []byte
	for i < n {
		c := text[i]
		if c == '\n' {
			return string(buf), i + 1, line + 1, fs
		}
		if c == '\r' {
			fs = append(fs, PRFinding{Reason: PRReasonStrayCR, Line: line})
			if i+1 < n && text[i+1] == '\n' {
				return string(buf), i + 2, line + 1, fs
			}
			return string(buf), i + 1, line + 1, fs
		}
		if c < 0x20 {
			fs = append(fs, PRFinding{Reason: PRReasonBareControlInValue,
				Line: line, Detail: prItoa(int64(c))})
			buf = append(buf, c)
			i++
			continue
		}
		if c == '\\' {
			if i+1 >= n {
				fs = append(fs, PRFinding{Reason: PRReasonDanglingContinue, Line: line})
				return string(buf), i + 1, line, fs
			}
			next := text[i+1]
			if next == '\n' {
				i += 2
				line++
				for i < n && (text[i] == ' ' || text[i] == '\t') {
					i++
				}
				continue
			}
			if next == '\r' {
				fs = append(fs, PRFinding{Reason: PRReasonStrayCR, Line: line})
				if i+2 < n && text[i+2] == '\n' {
					i += 3
					line++
				} else {
					i += 2
					line++
				}
				for i < n && (text[i] == ' ' || text[i] == '\t') {
					i++
				}
				continue
			}
			if next == 'u' {
				ch, ok, adv := prReadUnicode(text, i)
				if !ok {
					fs = append(fs, PRFinding{Reason: PRReasonMalformedUnicode, Line: line})
					buf = append(buf, '?')
				} else {
					buf = append(buf, ch...)
					if prIsCRLF(ch) {
						fs = append(fs, PRFinding{Reason: PRReasonBareControlInValue, Line: line})
					}
				}
				i += adv
				continue
			}
			buf = append(buf, prUnescape(next))
			i += 2
			continue
		}
		buf = append(buf, c)
		i++
	}
	return string(buf), i, line, fs
}

// prReadUnicode 从反斜杠位置解析 \uXXXX，adv 为消费字节数。
func prReadUnicode(text string, i int) (ch string, ok bool, adv int) {
	if i+5 >= len(text) {
		return "", false, len(text) - i
	}
	var v rune
	for k := 2; k <= 5; k++ {
		c := text[i+k]
		d := prHexVal(c)
		if d < 0 {
			return "", false, 6
		}
		v = v*16 + rune(d)
	}
	return string(rune(v)), true, 6
}

func prHexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func prUnescape(c byte) byte {
	switch c {
	case 't':
		return '\t'
	case 'r':
		return '\r'
	case 'n':
		return '\n'
	case 'f':
		return 0x0c
	}
	return c
}

func prIsCRLF(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			return true
		}
	}
	return false
}

func prKeyHasSpace(k string) bool {
	for i := 0; i < len(k); i++ {
		if k[i] == ' ' || k[i] == '\t' {
			return true
		}
	}
	return false
}

func prItoa(i int64) string {
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

// PRHasReason 判定结果含某类问题。
func PRHasReason(res PRParseResult, reason string) bool {
	for _, f := range res.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
