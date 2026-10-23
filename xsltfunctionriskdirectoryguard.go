package main

// xsltfunctionriskdirectoryguard.go —— XSLT 危险函数目录。
//
// 威胁模型：
//   document() 可读任意 URL/文件，script/import/java: 可执行代码，
//   不可信 XSLT 应禁用这些函数。纯字符查表，不用正则。

const (
	XSLClassBlock   = "block"
	XSLClassWarn    = "warn"
	XSLClassAllow   = "allow"
	XSLClassUnknown = "unknown"
)

var XSLBlock = []string{
	"document()",
	"script",
	"java:",
	"runtime",
	"exec",
	"import",
	"include",
}

var XSLWarn = []string{
	"xsl:message",
	"xsl:fallback",
}

var XSLAllow = []string{
	"value-of",
	"xsl:template",
}

func XSLLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func XSLIn(list []string, v string) bool {
	for _, x := range list { if XSLLower(x) == v { return true } }
	return false
}

// XSLClassify 分类单个令牌。
func XSLClassify(tok string) string {
	v := XSLLower(tok)
	switch {
	case XSLIn(XSLBlock, v): return XSLClassBlock
	case XSLIn(XSLWarn, v): return XSLClassWarn
	case XSLIn(XSLAllow, v): return XSLClassAllow
	default: return XSLClassUnknown
	}
}
