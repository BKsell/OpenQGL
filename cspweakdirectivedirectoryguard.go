package main

// cspweakdirectivedirectoryguard.go —— CSP 危险指令取值目录。
//
// 威胁模型：
//   default-src/script-src 出现 *、'unsafe-inline'、'unsafe-eval' 即基本失去防 XSS 能力，
//   data: 脚本源也应禁止。纯字符查表，不用正则。

const (
	CNNClassBlock   = "block"
	CNNClassWarn    = "warn"
	CNNClassAllow   = "allow"
	CNNClassUnknown = "unknown"
)

var CNNBlock = []string{
	"*",
	"unsafe-inline",
	"unsafe-eval",
	"data:",
	"strict-dynamic-without-nonce",
}

var CNNWarn = []string{
	"strict-dynamic",
	"https:",
	"blob:",
}

var CNNAllow = []string{
	"self",
	"nonce",
	"sha256-",
	"none",
}

func CNNLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CNNIn(list []string, v string) bool {
	for _, x := range list { if CNNLower(x) == v { return true } }
	return false
}

// CNNClassify 分类单个令牌。
func CNNClassify(tok string) string {
	v := CNNLower(tok)
	switch {
	case CNNIn(CNNBlock, v): return CNNClassBlock
	case CNNIn(CNNWarn, v): return CNNClassWarn
	case CNNIn(CNNAllow, v): return CNNClassAllow
	default: return CNNClassUnknown
	}
}
