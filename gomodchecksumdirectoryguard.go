package main

// gomodchecksumdirectoryguard.go —— Go module 校验绕过目录。
//
// 威胁模型：
//   GONOSUMCHECK/GOFLAGS -insecure/GOPRIVATE 过宽、replace 本地路径会绕过 sumdb 校验，
//   应保留 sum.golang.org 校验。纯字符查表，不用正则。

const (
	GMPClassBlock   = "block"
	GMPClassWarn    = "warn"
	GMPClassAllow   = "allow"
	GMPClassUnknown = "unknown"
)

var GMPBlock = []string{
	"gonosumcheck",
	"goinsecure",
	"goflags-insecure",
	"replace-local",
	"goprivate-*",
}

var GMPWarn = []string{
	"goproxy=direct",
}

var GMPAllow = []string{
	"sum.golang.org",
	"goproxy-https",
}

func GMPLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func GMPIn(list []string, v string) bool {
	for _, x := range list { if GMPLower(x) == v { return true } }
	return false
}

// GMPClassify 分类单个令牌。
func GMPClassify(tok string) string {
	v := GMPLower(tok)
	switch {
	case GMPIn(GMPBlock, v): return GMPClassBlock
	case GMPIn(GMPWarn, v): return GMPClassWarn
	case GMPIn(GMPAllow, v): return GMPClassAllow
	default: return GMPClassUnknown
	}
}
