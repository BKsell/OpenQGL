package main

// hpkppindirectoryguard.go —— 已弃用 HPKP 钉扎头目录。
//
// 威胁模型：
//   Public-Key-Pins/Report-Only 已被主流浏览器移除，错误钉扎会长期锁死站点，
//   不应再下发，出现即阻断。纯字符查表，不用正则。

const (
	HPKClassBlock   = "block"
	HPKClassWarn    = "warn"
	HPKClassAllow   = "allow"
	HPKClassUnknown = "unknown"
)

var HPKBlock = []string{
	"public-key-pins",
	"public-key-pins-report-only",
	"pin-sha256",
}

var HPKWarn = []string{
	"max-age",
	"includesubdomains",
}

var HPKAllow = []string{
	"report-uri",
}

func HPKLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func HPKIn(list []string, v string) bool {
	for _, x := range list { if HPKLower(x) == v { return true } }
	return false
}

// HPKClassify 分类单个令牌。
func HPKClassify(tok string) string {
	v := HPKLower(tok)
	switch {
	case HPKIn(HPKBlock, v): return HPKClassBlock
	case HPKIn(HPKWarn, v): return HPKClassWarn
	case HPKIn(HPKAllow, v): return HPKClassAllow
	default: return HPKClassUnknown
	}
}
