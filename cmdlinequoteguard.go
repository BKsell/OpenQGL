package main

// cmdlinequoteguard.go —— Windows 命令行参数拼接的引号/元字符注入守卫。
//
// 背景：
//   启动器要拼命令行启动 javaw.exe、外部工具并传入含空格的路径（如
//   C:\Program Files\Java\...）与玩家自定义参数。Windows 命令行由程序自行解析（无 argv 数组的
//   系统级保证），CreateProcess 的 lpCommandLine 是一整串，拼接不当时：
//     - 路径含空格未加引号，被拆成两个 token，可能执行到更早目录里的程序；
//     - 参数值里的 " 未转义（正确规则为 " -> ""），可提前闭合引号注入额外开关/程序；
//     - 参数以反斜杠结尾紧贴引号（...\" ），反斜杠会转义引号，边界被吃掉；
//     - 出现命令元字符（& | > < ^）或未配对引号。
//   纯字符串判定与"按 CRT 规则重新安全引用"，不真正创建进程，不使用正则。

const (
	CQReasonUnquotedSpace     = "cmdline-exe-path-with-space-not-quoted"
	CQReasonUnescapedQuote    = "cmdline-argument-double-quote-not-doubled"
	CQReasonTrailingBackslash = "cmdline-argument-trailing-backslash-before-quote"
	CQReasonShellMetachar     = "cmdline-argument-contains-shell-metacharacter"
	CQReasonUnbalancedQuotes  = "cmdline-unbalanced-double-quotes"
)

// CQFinding 记录一处命令行拼接问题。
type CQFinding struct {
	Reason string
	Detail string
}

// CQAuditExePath 审计可执行文件路径是否被安全引用。
func CQAuditExePath(raw string) (safe bool, findings []CQFinding) {
	if raw == "" {
		return false, []CQFinding{{Reason: CQReasonUnquotedSpace, Detail: "empty"}}
	}
	if cqContainsAny(raw, " \t") {
		if !(raw[0] == '"' && raw[len(raw)-1] == '"') {
			findings = append(findings, CQFinding{Reason: CQReasonUnquotedSpace})
		}
	}
	if cqContainsAny(raw, "&|<>^") {
		findings = append(findings, CQFinding{Reason: CQReasonShellMetachar, Detail: "exe"})
	}
	return len(findings) == 0, findings
}

// CQQuoteArgument 按 MSVCRT/CommandLineToArgvW 规则把单个参数安全引用。
// 规则：若参数含空格/tab/引号，则整体加双引号；内部反斜杠仅在紧贴引号或结尾时翻倍，
// 内部双引号翻倍为两个双引号。
func CQQuoteArgument(arg string) string {
	if !cqNeedsQuoting(arg) {
		return arg
	}
	var out []byte
	out = append(out, '"')
	backslashes := 0
	for i := 0; i < len(arg); i++ {
		c := arg[i]
		switch c {
		case '\\':
			backslashes++
			out = append(out, '\\')
		case '"':
			// 前面的反斜杠先翻倍，再把引号翻倍
			for k := 0; k < backslashes; k++ {
				out = append(out, '\\')
			}
			backslashes = 0
			out = append(out, '"', '"')
		default:
			backslashes = 0
			out = append(out, c)
		}
	}
	// 结尾反斜杠在闭合引号前需翻倍
	for k := 0; k < backslashes; k++ {
		out = append(out, '\\')
	}
	out = append(out, '"')
	return string(out)
}

// CQAuditArgument 审计一个"调用方手写引用"的参数值是否符合安全规则。
func CQAuditArgument(value string) (safe bool, findings []CQFinding) {
	if cqContainsAny(value, "&|<>^") {
		findings = append(findings, CQFinding{Reason: CQReasonShellMetachar})
	}
	if cqContainsByte(value, '"') {
		// 若出现孤立 '"'（未成对出现），视为未正确转义
		if !cqAllQuotesDoubled(value) {
			findings = append(findings, CQFinding{Reason: CQReasonUnescapedQuote})
		}
	}
	// 以奇数个反斜杠结尾且整体带引号时，结尾反斜杠会吃掉闭合引号
	if cqOddTrailingBackslashes(value) && cqContainsByte(value, '"') {
		findings = append(findings, CQFinding{Reason: CQReasonTrailingBackslash})
	}
	if cqUnbalancedQuotes(value) {
		findings = append(findings, CQFinding{Reason: CQReasonUnbalancedQuotes})
	}
	return len(findings) == 0, findings
}

func cqNeedsQuoting(s string) bool {
	return cqContainsAny(s, " \t\"")
}

func cqAllQuotesDoubled(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			if i+1 >= len(s) || s[i+1] != '"' {
				return false
			}
			i++
		}
	}
	return true
}

func cqOddTrailingBackslashes(s string) bool {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

func cqUnbalancedQuotes(s string) bool {
	q := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			q++
		}
	}
	return q%2 == 1
}

func cqContainsAny(s, set string) bool {
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(set); j++ {
			if s[i] == set[j] {
				return true
			}
		}
	}
	return false
}

func cqContainsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

// CQHasReason 判定结果含某类问题。
func CQHasReason(findings []CQFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
