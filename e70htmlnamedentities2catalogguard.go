package main

// e70htmlnamedentities2catalogguard.go —— 扩展 HTML 命名实体目录。
//
// 威胁模型：
//   &lpar; &rpar; &semi; 等命名实体由 HTML 解析器还原为标点，纯字节匹配会漏报，
//   危险字符命名实体应阻断。纯字符查表，不用正则。

const (
	E70HN2ClassBlock   = "block"
	E70HN2ClassWarn    = "warn"
	E70HN2ClassAllow   = "allow"
	E70HN2ClassUnknown = "unknown"
)

var E70HN2Block = []string{
	"&lpar;",
	"&rpar;",
	"&period;",
	"&equals;",
	"&commat;",
	"&lbrace;",
	"&rbrace;",
}

var E70HN2Warn = []string{
	"&excl;",
	"&num;",
	"&dollar;",
	"&percnt;",
	"&ast;",
	"&plus;",
	"&comma;",
	"&colon;",
	"&semi;",
	"&lowbar;",
	"&tilde;",
}

var E70HN2Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70HN2Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70HN2In(list []string, v string) bool {
	for _, x := range list { if E70HN2Lower(x) == v { return true } }
	return false
}

// E70HN2Classify 分类单个令牌。
func E70HN2Classify(tok string) string {
	v := E70HN2Lower(tok)
	switch {
	case E70HN2In(E70HN2Block, v): return E70HN2ClassBlock
	case E70HN2In(E70HN2Warn, v): return E70HN2ClassWarn
	case E70HN2In(E70HN2Allow, v): return E70HN2ClassAllow
	default: return E70HN2ClassUnknown
	}
}
