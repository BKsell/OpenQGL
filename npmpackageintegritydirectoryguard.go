package main

// npmpackageintegritydirectoryguard.go —— npm 依赖来源/完整性风险目录。
//
// 威胁模型：
//   resolved 走 http、缺 integrity、link:/file:/git+ 与 * 浮动版本可被替换或抢注，
//   应锁定 https + sha512。纯字符查表，不用正则。

const (
	NPDClassBlock   = "block"
	NPDClassWarn    = "warn"
	NPDClassAllow   = "allow"
	NPDClassUnknown = "unknown"
)

var NPDBlock = []string{
	"resolved-http",
	"no-integrity",
	"link:",
	"file:",
	"git+http",
	"version-*",
}

var NPDWarn = []string{
	"git+https",
	"^version",
	"~version",
}

var NPDAllow = []string{
	"https-sha512-pinned",
}

func NPDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func NPDIn(list []string, v string) bool {
	for _, x := range list { if NPDLower(x) == v { return true } }
	return false
}

// NPDClassify 分类单个令牌。
func NPDClassify(tok string) string {
	v := NPDLower(tok)
	switch {
	case NPDIn(NPDBlock, v): return NPDClassBlock
	case NPDIn(NPDWarn, v): return NPDClassWarn
	case NPDIn(NPDAllow, v): return NPDClassAllow
	default: return NPDClassUnknown
	}
}
