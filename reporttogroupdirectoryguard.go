package main

// reporttogroupdirectoryguard.go —— Reporting API 组配置目录。
//
// 威胁模型：
//   max_age=0 等于关闭报告端点，include_subdomains 扩大收集面，
//   错误上报端点要 https 且限域。纯字符查表，不用正则。

const (
	RTEClassBlock   = "block"
	RTEClassWarn    = "warn"
	RTEClassAllow   = "allow"
	RTEClassUnknown = "unknown"
)

var RTEBlock = []string{
	"max_age=0",
	"http://",
}

var RTEWarn = []string{
	"include_subdomains",
	"group",
}

var RTEAllow = []string{
	"max_age",
	"endpoints",
	"https://",
}

func RTELower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func RTEIn(list []string, v string) bool {
	for _, x := range list { if RTELower(x) == v { return true } }
	return false
}

// RTEClassify 分类单个令牌。
func RTEClassify(tok string) string {
	v := RTELower(tok)
	switch {
	case RTEIn(RTEBlock, v): return RTEClassBlock
	case RTEIn(RTEWarn, v): return RTEClassWarn
	case RTEIn(RTEAllow, v): return RTEClassAllow
	default: return RTEClassUnknown
	}
}
