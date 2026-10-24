package main

// e69htmlnamedentitiescatalogguard.go —— HTML 命名实体字节目录。
//
// 威胁模型：
//   &quot; &lt; &sol; &Tab; 等命名实体由 HTML 解析器还原为危险字符，纯字节匹配会漏报，
//   危险字符命名实体应阻断。纯字符查表，不用正则。

const (
	E69HNEClassBlock   = "block"
	E69HNEClassWarn    = "warn"
	E69HNEClassAllow   = "allow"
	E69HNEClassUnknown = "unknown"
)

var E69HNEBlock = []string{
	"&NewLine;",
	"&quot;",
	"&apos;",
	"&sol;",
	"&lt;",
	"&gt;",
	"&bsol;",
}

var E69HNEWarn = []string{
	"&Tab;",
	"&amp;",
}

var E69HNEAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69HNELower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69HNEIn(list []string, v string) bool {
	for _, x := range list { if E69HNELower(x) == v { return true } }
	return false
}

// E69HNEClassify 分类单个令牌。
func E69HNEClassify(tok string) string {
	v := E69HNELower(tok)
	switch {
	case E69HNEIn(E69HNEBlock, v): return E69HNEClassBlock
	case E69HNEIn(E69HNEWarn, v): return E69HNEClassWarn
	case E69HNEIn(E69HNEAllow, v): return E69HNEClassAllow
	default: return E69HNEClassUnknown
	}
}
