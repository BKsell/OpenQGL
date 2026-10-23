package main

// longpathcomponentdirectoryguard.go —— 超长路径段目录。
//
// 威胁模型：
//   路径段超长或 \\?\ 长路径前缀可绕过部分长度限制检查，
//   应统一规范化长度再判定。纯字符查表，不用正则。

const (
	MPLClassBlock   = "block"
	MPLClassWarn    = "warn"
	MPLClassAllow   = "allow"
	MPLClassUnknown = "unknown"
)

var MPLBlock = []string{
	"\\\\?\\",
	"260-limit",
	"nul-terminator-long",
}

var MPLWarn = []string{
	"long-path",
}

var MPLAllow = []string{
	"short-canonical",
}

func MPLLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func MPLIn(list []string, v string) bool {
	for _, x := range list { if MPLLower(x) == v { return true } }
	return false
}

// MPLClassify 分类单个令牌。
func MPLClassify(tok string) string {
	v := MPLLower(tok)
	switch {
	case MPLIn(MPLBlock, v): return MPLClassBlock
	case MPLIn(MPLWarn, v): return MPLClassWarn
	case MPLIn(MPLAllow, v): return MPLClassAllow
	default: return MPLClassUnknown
	}
}
