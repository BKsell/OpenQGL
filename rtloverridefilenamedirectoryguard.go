package main

// rtloverridefilenamedirectoryguard.go —— 文件名 Unicode 方向控制目录。
//
// 威胁模型：
//   U+202E 等双向控制字符可把 .exe 视觉上显示成 .png 钓鱼，
//   落盘文件名应拒绝双向覆盖符。纯字符查表，不用正则。

const (
	RTLClassBlock   = "block"
	RTLClassWarn    = "warn"
	RTLClassAllow   = "allow"
	RTLClassUnknown = "unknown"
)

var RTLBlock = []string{
	"u+202e",
	"u+200f",
	"u+202d",
	"u+202c",
}

var RTLWarn = []string{
	"u+200e",
	"bidi-control",
}

var RTLAllow = []string{
	"plain",
}

func RTLLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func RTLIn(list []string, v string) bool {
	for _, x := range list { if RTLLower(x) == v { return true } }
	return false
}

// RTLClassify 分类单个令牌。
func RTLClassify(tok string) string {
	v := RTLLower(tok)
	switch {
	case RTLIn(RTLBlock, v): return RTLClassBlock
	case RTLIn(RTLWarn, v): return RTLClassWarn
	case RTLIn(RTLAllow, v): return RTLClassAllow
	default: return RTLClassUnknown
	}
}
