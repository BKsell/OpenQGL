package main

// doubleextensionhidingdirectoryguard.go —— 双扩展名伪装目录。
//
// 威胁模型：
//   .pdf.exe/.jpg.scr 等双扩展利用资源管理器隐藏真实可执行扩展，
//   应以最后一个扩展名判定并警告多扩展名。纯字符查表，不用正则。

const (
	DEXClassBlock   = "block"
	DEXClassWarn    = "warn"
	DEXClassAllow   = "allow"
	DEXClassUnknown = "unknown"
)

var DEXBlock = []string{
	".exe.jpg",
	".pdf.exe",
	".scr.pdf",
	".bat.txt",
	".com.png",
	".pif.jpg",
}

var DEXWarn = []string{
	"trailing-space-ext",
	"double-ext",
}

var DEXAllow = []string{
	"single-ext",
}

func DEXLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func DEXIn(list []string, v string) bool {
	for _, x := range list { if DEXLower(x) == v { return true } }
	return false
}

// DEXClassify 分类单个令牌。
func DEXClassify(tok string) string {
	v := DEXLower(tok)
	switch {
	case DEXIn(DEXBlock, v): return DEXClassBlock
	case DEXIn(DEXWarn, v): return DEXClassWarn
	case DEXIn(DEXAllow, v): return DEXClassAllow
	default: return DEXClassUnknown
	}
}
