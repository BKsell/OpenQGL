package main

// e70batakcatalogguard.go —— 巴塔克文字码位目录。
//
// 威胁模型：
//   巴塔克文罕用且渲染依赖字体，可隐藏数据，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T31ClassBlock   = "block"
	E70T31ClassWarn    = "warn"
	E70T31ClassAllow   = "allow"
	E70T31ClassUnknown = "unknown"
)

var E70T31Block = []string{
	"U+1BC0",
	"U+1BC1",
	"U+1BC2",
	"U+1BC3",
	"U+1BC4",
	"U+1BC5",
	"U+1BC6",
	"U+1BC7",
	"U+1BC8",
	"U+1BC9",
	"U+1BCA",
	"U+1BCB",
	"U+1BCC",
	"U+1BCD",
	"U+1BCE",
	"U+1BCF",
	"U+1BD0",
	"U+1BD1",
	"U+1BD2",
	"U+1BD3",
	"U+1BD4",
	"U+1BD5",
	"U+1BD6",
	"U+1BD7",
	"U+1BD8",
	"U+1BD9",
	"U+1BDA",
	"U+1BDB",
	"U+1BDC",
	"U+1BDD",
	"U+1BDE",
	"U+1BDF",
	"U+1BE0",
	"U+1BE1",
	"U+1BE2",
	"U+1BE3",
	"U+1BE4",
	"U+1BE5",
	"U+1BE6",
	"U+1BE7",
	"U+1BE8",
	"U+1BE9",
	"U+1BEA",
	"U+1BEB",
	"U+1BEC",
	"U+1BED",
	"U+1BEE",
	"U+1BEF",
	"U+1BF0",
	"U+1BF1",
	"U+1BF2",
	"U+1BF3",
	"U+1BF4",
	"U+1BF5",
	"U+1BF6",
	"U+1BF7",
	"U+1BF8",
	"U+1BF9",
	"U+1BFA",
	"U+1BFB",
	"U+1BFC",
	"U+1BFD",
	"U+1BFE",
	"U+1BFF",
}

var E70T31Warn = []string{
}

var E70T31Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T31Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T31In(list []string, v string) bool {
	for _, x := range list { if E70T31Lower(x) == v { return true } }
	return false
}

// E70T31Classify 分类单个令牌。
func E70T31Classify(tok string) string {
	v := E70T31Lower(tok)
	switch {
	case E70T31In(E70T31Block, v): return E70T31ClassBlock
	case E70T31In(E70T31Warn, v): return E70T31ClassWarn
	case E70T31In(E70T31Allow, v): return E70T31ClassAllow
	default: return E70T31ClassUnknown
	}
}
