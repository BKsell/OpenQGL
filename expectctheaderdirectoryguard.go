package main

// expectctheaderdirectoryguard.go —— 已弃用 Expect-CT 头目录。
//
// 威胁模型：
//   Expect-CT 已随 CT 强制化退役，继续下发无意义且可能误导合规判断，
//   应移除。纯字符查表，不用正则。

const (
	ECTClassBlock   = "block"
	ECTClassWarn    = "warn"
	ECTClassAllow   = "allow"
	ECTClassUnknown = "unknown"
)

var ECTBlock = []string{
	"expect-ct",
	"enforce",
}

var ECTWarn = []string{
	"report-uri",
	"max-age",
}

var ECTAllow = []string{
	"strict-transport-security",
}

func ECTLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func ECTIn(list []string, v string) bool {
	for _, x := range list { if ECTLower(x) == v { return true } }
	return false
}

// ECTClassify 分类单个令牌。
func ECTClassify(tok string) string {
	v := ECTLower(tok)
	switch {
	case ECTIn(ECTBlock, v): return ECTClassBlock
	case ECTIn(ECTWarn, v): return ECTClassWarn
	case ECTIn(ECTAllow, v): return ECTClassAllow
	default: return ECTClassUnknown
	}
}
