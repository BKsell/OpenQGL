package main

// logforgeryguard.go —— 日志注入 / 伪造（CRLF Injection、终端转义、伪造级别前缀）净化内核。
//
// 背景：
//   启动器会把用户名、服务器地址、版本隔离名、整合包名、错误返回体等"外部可控字符串"
//   写进本地日志与上报。攻击者控制的 Minecraft 服务器 MOTD、下载 URL、账号昵称里若带
//   换行，就能在按行组织的日志里伪造一整行，例如插入假的 "[ERROR] token leaked ..."、
//   伪造审计记录、把脏数据嫁祸给其它模块；带 \r 还能在终端 / 控制台里覆盖当前行。
//   此外 ANSI 转义序列（ESC[...）可在支持转义的终端里移动光标、清屏、改色，进一步
//   掩盖痕迹或制造误导。
//
// 本模块是纯字节 / 字符串处理，不使用正则：
//   1. 检出 CR、LF、垂直制表、换页等可断行字符；
//   2. 检出 ESC（0x1b）引导的 ANSI / 终端控制序列；
//   3. 检出 Unicode 行分隔 U+2028 / 段分隔 U+2029 / NEL U+0085；
//   4. 检出字符串以伪造日志级别 / 时间戳前缀开头；
//   5. 提供 Safe 版本：把上述字符替换成可见占位，返回可安全落盘 / 上屏的单行文本。

const (
	LFGReasonCRLF          = "lfg-line-break-injection"
	LFGReasonCarriage      = "lfg-carriage-return"
	LFGReasonANSI          = "lfg-ansi-escape-sequence"
	LFGReasonUnicodeLine   = "lfg-unicode-line-separator"
	LFGReasonNullByte      = "lfg-null-byte"
	LFGReasonForgedLevel   = "lfg-forged-level-prefix"
	LFGReasonControlChar   = "lfg-other-control-character"
)

// LFGPolicy 控制日志净化严格度。
type LFGPolicy struct {
	BlockLineBreaks    bool // 拦截 \n \r \v \f
	BlockANSI          bool // 拦截 ESC 转义
	BlockUnicodeLine   bool // 拦截 U+2028 U+2029 U+0085
	BlockControlBytes  bool // 拦截其余 C0 控制字符（除 \t）
	BlockForgedPrefix  bool // 拦截伪造级别 / 时间戳前缀
	MaxFieldBytes      int  // 单字段最大字节数
}

// LFGFinding 记录一处日志注入风险。
type LFGFinding struct {
	Reason string
	Offset int
	Detail string
}

// DefaultLFGPolicy 返回默认严格策略。
func DefaultLFGPolicy() LFGPolicy {
	return LFGPolicy{
		BlockLineBreaks:   true,
		BlockANSI:         true,
		BlockUnicodeLine:  true,
		BlockControlBytes: true,
		BlockForgedPrefix: true,
		MaxFieldBytes:     4096,
	}
}

// lfgForgedPrefixes 为可伪造的行首标记（小写比较）。
var lfgForgedPrefixes = []string{
	"[error]", "[warn]", "[warning]", "[info]", "[debug]", "[fatal]", "[trace]",
	"error:", "warn:", "info:", "debug:", "fatal:",
}

// lfgLowerASCII 归一小写。
func lfgLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// lfgHasPrefixFold 判断 s 是否以小写 prefix 开头（ASCII 大小写不敏感）。
func lfgHasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if lfgLowerASCII(s[i]) != prefix[i] {
			return false
		}
	}
	return true
}

// lfgStartsForged 判断字符串开头是否像伪造的日志级别 / 时间戳。
func lfgStartsForged(s string) bool {
	// 跳过前导空白。
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	rest := s[i:]
	for _, p := range lfgForgedPrefixes {
		if lfgHasPrefixFold(rest, p) {
			return true
		}
	}
	return false
}

// LFGScan 扫描一个将写入日志的外部字段。
func LFGScan(field string, pol LFGPolicy) []LFGFinding {
	var out []LFGFinding
	if pol.MaxFieldBytes > 0 && len(field) > pol.MaxFieldBytes {
		out = append(out, LFGFinding{Reason: LFGReasonControlChar, Offset: pol.MaxFieldBytes, Detail: "field-too-long"})
	}
	if pol.BlockForgedPrefix && lfgStartsForged(field) {
		out = append(out, LFGFinding{Reason: LFGReasonForgedLevel, Offset: 0})
	}
	for i := 0; i < len(field); {
		b := field[i]
		// UTF-8 多字节序列：识别 U+2028（E2 80 A8）、U+2029（E2 80 A9）、U+0085（C2 85）。
		if pol.BlockUnicodeLine && b == 0xe2 && i+2 < len(field) &&
			field[i+1] == 0x80 && (field[i+2] == 0xa8 || field[i+2] == 0xa9) {
			out = append(out, LFGFinding{Reason: LFGReasonUnicodeLine, Offset: i})
			i += 3
			continue
		}
		if pol.BlockUnicodeLine && b == 0xc2 && i+1 < len(field) && field[i+1] == 0x85 {
			out = append(out, LFGFinding{Reason: LFGReasonUnicodeLine, Offset: i})
			i += 2
			continue
		}
		if b < 0x80 {
			switch {
			case b == '\n' || b == '\v' || b == '\f':
				if pol.BlockLineBreaks {
					out = append(out, LFGFinding{Reason: LFGReasonCRLF, Offset: i})
				}
			case b == '\r':
				if pol.BlockLineBreaks {
					out = append(out, LFGFinding{Reason: LFGReasonCarriage, Offset: i})
				}
			case b == 0x1b:
				if pol.BlockANSI {
					out = append(out, LFGFinding{Reason: LFGReasonANSI, Offset: i})
				}
			case b == 0:
				if pol.BlockControlBytes {
					out = append(out, LFGFinding{Reason: LFGReasonNullByte, Offset: i})
				}
			case b < 0x20 && b != '\t':
				if pol.BlockControlBytes {
					out = append(out, LFGFinding{Reason: LFGReasonControlChar, Offset: i})
				}
			case b == 0x7f:
				if pol.BlockControlBytes {
					out = append(out, LFGFinding{Reason: LFGReasonControlChar, Offset: i})
				}
			}
			i++
			continue
		}
		// 其它多字节 UTF-8：按首字节长度整体跳过，避免把尾字节当 ASCII 扫描。
		size := 1
		switch {
		case b&0xe0 == 0xc0:
			size = 2
		case b&0xf0 == 0xe0:
			size = 3
		case b&0xf8 == 0xf0:
			size = 4
		}
		i += size
	}
	return out
}

// LFGSanitize 返回可安全单行落盘的文本：危险字符替换为可见占位，超长截断。
func LFGSanitize(field string, pol LFGPolicy) string {
	out := make([]byte, 0, len(field))
	for i := 0; i < len(field); {
		b := field[i]
		// Unicode 行分隔整体替换。
		if b == 0xe2 && i+2 < len(field) && field[i+1] == 0x80 &&
			(field[i+2] == 0xa8 || field[i+2] == 0xa9) {
			out = append(out, '?')
			i += 3
			continue
		}
		if b == 0xc2 && i+1 < len(field) && field[i+1] == 0x85 {
			out = append(out, '?')
			i += 2
			continue
		}
		if b < 0x80 {
			switch {
			case b == '\n' || b == '\r' || b == '\v' || b == '\f':
				out = append(out, '\\', 'x')
				out = append(out, lfgHex2(b)...)
			case b == 0x1b:
				out = append(out, '?')
			case b == 0:
				out = append(out, '?')
			case b < 0x20 && b != '\t':
				out = append(out, '?')
			case b == 0x7f:
				out = append(out, '?')
			default:
				out = append(out, b)
			}
			i++
			continue
		}
		size := 1
		switch {
		case b&0xe0 == 0xc0:
			size = 2
		case b&0xf0 == 0xe0:
			size = 3
		case b&0xf8 == 0xf0:
			size = 4
		}
		for k := 0; k < size && i+k < len(field); k++ {
			out = append(out, field[i+k])
		}
		i += size
	}
	res := string(out)
	if pol.MaxFieldBytes > 0 && len(res) > pol.MaxFieldBytes {
		res = res[:pol.MaxFieldBytes]
	}
	return res
}

// lfgHex2 返回单字节两位大写十六进制。
func lfgHex2(b byte) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{hex[b>>4], hex[b&0x0f]})
}

// LFGIsSafe 便捷判定。
func LFGIsSafe(field string) bool {
	return len(LFGScan(field, DefaultLFGPolicy())) == 0
}
