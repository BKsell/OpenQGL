package main

// predictabletmppathdirectoryguard.go —— 可预测临时文件路径目录。
//
// 威胁模型：
//   固定 /tmp 名、PID 命名、无 0600 的临时文件可被符号链接抢占/抢注，
//   应用 mkstemp 风格随机名并限权。纯字符查表，不用正则。

const (
	TMPClassBlock   = "block"
	TMPClassWarn    = "warn"
	TMPClassAllow   = "allow"
	TMPClassUnknown = "unknown"
)

var TMPBlock = []string{
	"/tmp/fixed",
	"pid-name",
	"mktemp-none",
	"world-tmp",
}

var TMPWarn = []string{
	"shared-tmp",
}

var TMPAllow = []string{
	"mkstemp-0600",
}

func TMPLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func TMPIn(list []string, v string) bool {
	for _, x := range list { if TMPLower(x) == v { return true } }
	return false
}

// TMPClassify 分类单个令牌。
func TMPClassify(tok string) string {
	v := TMPLower(tok)
	switch {
	case TMPIn(TMPBlock, v): return TMPClassBlock
	case TMPIn(TMPWarn, v): return TMPClassWarn
	case TMPIn(TMPAllow, v): return TMPClassAllow
	default: return TMPClassUnknown
	}
}
