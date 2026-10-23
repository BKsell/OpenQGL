package main

// loginjectionguard.go —— 写入日志的外部可控值净化（日志伪造/CRLF 注入）。
//
// 背景：
//   启动器会把服务器地址、玩家名、错误回显、mod 文件名等外部可控字符串写进文本日志（并可能被
//   上传排查）。若值里含 CR/LF，攻击者可伪造一整行"INFO 鉴权成功"之类的假记录，干扰审计；控制字符
//   还能污染终端（ANSI 转义、光标移动、清屏）。本模块：
//     - 检测值中的 CR/LF/NUL 与其它 C0 控制字符；
//     - 检测 ANSI 转义序列起始（ESC 0x1b）；
//     - 提供 SSanitizeLog：把危险字符替换为安全占位，返回可安全单行写入的文本；
//   纯字节处理，不使用正则。

const (
	LIReasonCRLF       = "log-value-contains-crlf-line-break"
	LIReasonControl    = "log-value-contains-c0-control-character"
	LIReasonANSIEscape = "log-value-contains-ansi-escape"
	LIReasonNUL        = "log-value-contains-nul-byte"
)

// LIFinding 记录一处日志注入问题。
type LIFinding struct {
	Reason string
	Index  int
}

// LIAuditValue 审计待写日志的原始值。
func LIAuditValue(value string) (safe bool, findings []LIFinding) {
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '\r' || c == '\n':
			findings = append(findings, LIFinding{Reason: LIReasonCRLF, Index: i})
		case c == 0:
			findings = append(findings, LIFinding{Reason: LIReasonNUL, Index: i})
		case c == 0x1b:
			findings = append(findings, LIFinding{Reason: LIReasonANSIEscape, Index: i})
		case c < 0x20 || c == 0x7f:
			findings = append(findings, LIFinding{Reason: LIReasonControl, Index: i})
		}
	}
	return len(findings) == 0, findings
}

// LISanitizeLog 返回去除/替换危险字符后的单行安全文本。
// CR/LF/其它控制字符与 NUL 替换为 '_'，ESC 替换为 '_'，删除 0x7f。
func LISanitizeLog(value string) string {
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\r' || c == '\n' || c == 0x1b || c < 0x20 || c == 0x7f {
			if c != 0x7f {
				out = append(out, '_')
			}
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// LIHasReason 判定结果含某类问题。
func LIHasReason(findings []LIFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
