package main

// winresnameguard.go —— Windows 保留设备名与 NTFS 备用数据流（ADS）路径守卫。
//
// 背景：
//   启动器在 Windows 写存档/下载/缓存。两类经典路径坑：
//     1. 保留设备名（不区分大小写、可带任意扩展名）：CON、PRN、AUX、NUL、COM1..COM9、
//        LPT1..LPT9，访问它们会落到设备而非普通文件，造成挂起/覆盖语义异常；
//     2. 备用数据流 normal.txt:secret、文件里带冒号的区段（Zone.Identifier 之外的任意 ADS），
//        以及结尾 "." / " "（Win32 会剥离）导致白名单/路径比较被绕过；
//        反斜杠 UNC \\?\ 前缀若未识别也会改变路径语义。
//   本模块对"最后一个路径分量"做判定；纯字符处理，不触碰真实文件系统，不使用正则。

const (
	WNReasonReservedDevice   = "windows-path-component-is-reserved-device-name"
	WNReasonAlternateStream  = "windows-path-contains-alternate-data-stream-colon"
	WNReasonTrailingDotSpace = "windows-path-component-trailing-dot-or-space"
	WNReasonExtendedPrefix   = "windows-path-uses-win32-extended-or-unc-prefix"
)

// WNFinding 记录一处问题。
type WNFinding struct {
	Reason string
	Comp   string
}

var wnReserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// WNAuditPath 审计一个 Windows 路径（可含正/反斜杠）。
func WNAuditPath(path string) (safe bool, findings []WNFinding) {
	p := path
	// 识别扩展长度/UNC 前缀
	if wnHasPrefixCI(p, `\\?\`) || wnHasPrefixCI(p, `\\.\`) {
		findings = append(findings, WNFinding{Reason: WNReasonExtendedPrefix, Comp: p[:4]})
	}
	for _, comp := range wnSplitComponents(p) {
		if comp == "" {
			continue
		}
		base := wnStripExt(comp)
		if wnReserved[wnUpper(base)] {
			findings = append(findings, WNFinding{Reason: WNReasonReservedDevice, Comp: comp})
		}
		// 分量内冒号（排除盘符如 C:）：盘符只出现在首个分量且形如 X:
		if wnHasStreamColon(comp) {
			findings = append(findings, WNFinding{Reason: WNReasonAlternateStream, Comp: comp})
		}
		last := comp[len(comp)-1]
		if last == '.' || last == ' ' {
			findings = append(findings, WNFinding{Reason: WNReasonTrailingDotSpace, Comp: comp})
		}
	}
	return len(findings) == 0, findings
}

func wnSplitComponents(p string) []string {
	var out []string
	cur := ""
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '\\' || p[i] == '/' {
			out = append(out, cur)
			cur = ""
			if i == len(p) {
				break
			}
			continue
		}
		cur += string(p[i])
	}
	return out
}

func wnStripExt(comp string) string {
	for i := len(comp) - 1; i >= 0; i-- {
		if comp[i] == '.' {
			return comp[:i]
		}
		if comp[i] == '\\' || comp[i] == '/' {
			break
		}
	}
	return comp
}

// wnHasStreamColon：分量含 ':' 且不是单纯盘符（单字母 + ':' 且在盘符位置由调用方分量判定）。
func wnHasStreamColon(comp string) bool {
	for i := 0; i < len(comp); i++ {
		if comp[i] == ':' {
			// 盘符形态：长度恰为 2 且首字符是字母
			if i == 1 && len(comp) == 2 {
				c := comp[0]
				if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
					return false
				}
			}
			return true
		}
	}
	return false
}

func wnHasPrefixCI(s, pre string) bool {
	if len(s) < len(pre) {
		return false
	}
	return wnUpper(s[:len(pre)]) == wnUpper(pre)
}

func wnUpper(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 0x20
		}
	}
	return string(b)
}

// WNHasReason 判定结果含某类问题。
func WNHasReason(findings []WNFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
