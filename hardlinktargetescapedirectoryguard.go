package main

// hardlinktargetescapedirectoryguard.go —— 硬链接越权目标目录。
//
// 威胁模型：
//   硬链接指向 /etc/passwd、System32 或 setuid 文件可在解包后篡改系统文件，
//   应拒绝跨目录硬链接。纯字符查表，不用正则。

const (
	HLTClassBlock   = "block"
	HLTClassWarn    = "warn"
	HLTClassAllow   = "allow"
	HLTClassUnknown = "unknown"
)

var HLTBlock = []string{
	"/etc/passwd",
	"/etc/shadow",
	"system32",
	"setuid",
	"/bin/su",
}

var HLTWarn = []string{
	"cross-dir",
	"cross-device",
}

var HLTAllow = []string{
	"same-dir",
}

func HLTLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func HLTIn(list []string, v string) bool {
	for _, x := range list { if HLTLower(x) == v { return true } }
	return false
}

// HLTClassify 分类单个令牌。
func HLTClassify(tok string) string {
	v := HLTLower(tok)
	switch {
	case HLTIn(HLTBlock, v): return HLTClassBlock
	case HLTIn(HLTWarn, v): return HLTClassWarn
	case HLTIn(HLTAllow, v): return HLTClassAllow
	default: return HLTClassUnknown
	}
}
