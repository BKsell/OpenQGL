package main

// e70ethiopicextcatalogguard.go —— 埃塞俄比亚扩展码位目录。
//
// 威胁模型：
//   埃塞俄比亚扩展音节罕用且渲染不稳定，可隐藏载荷，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T54ClassBlock   = "block"
	E70T54ClassWarn    = "warn"
	E70T54ClassAllow   = "allow"
	E70T54ClassUnknown = "unknown"
)

var E70T54Block = []string{
	"U+2D80",
	"U+2D81",
	"U+2D82",
	"U+2D83",
	"U+2D84",
	"U+2D85",
	"U+2D86",
	"U+2D87",
	"U+2D88",
	"U+2D89",
	"U+2D8A",
	"U+2D8B",
	"U+2D8C",
	"U+2D8D",
	"U+2D8E",
	"U+2D8F",
	"U+2D90",
	"U+2D91",
	"U+2D92",
	"U+2D93",
	"U+2D94",
	"U+2D95",
	"U+2D96",
	"U+2D97",
	"U+2D98",
	"U+2D99",
	"U+2D9A",
	"U+2D9B",
	"U+2D9C",
	"U+2D9D",
	"U+2D9E",
	"U+2D9F",
	"U+2DA0",
	"U+2DA1",
	"U+2DA2",
	"U+2DA3",
	"U+2DA4",
	"U+2DA5",
	"U+2DA6",
	"U+2DA7",
	"U+2DA8",
	"U+2DA9",
	"U+2DAA",
	"U+2DAB",
	"U+2DAC",
	"U+2DAD",
	"U+2DAE",
	"U+2DAF",
	"U+2DB0",
	"U+2DB1",
	"U+2DB2",
	"U+2DB3",
	"U+2DB4",
	"U+2DB5",
	"U+2DB6",
	"U+2DB7",
	"U+2DB8",
	"U+2DB9",
	"U+2DBA",
	"U+2DBB",
	"U+2DBC",
	"U+2DBD",
	"U+2DBE",
	"U+2DBF",
	"U+2DC0",
	"U+2DC1",
	"U+2DC2",
	"U+2DC3",
	"U+2DC4",
	"U+2DC5",
	"U+2DC6",
	"U+2DC7",
	"U+2DC8",
	"U+2DC9",
	"U+2DCA",
	"U+2DCB",
	"U+2DCC",
	"U+2DCD",
	"U+2DCE",
	"U+2DCF",
	"U+2DD0",
	"U+2DD1",
	"U+2DD2",
	"U+2DD3",
	"U+2DD4",
	"U+2DD5",
	"U+2DD6",
	"U+2DD7",
	"U+2DD8",
	"U+2DD9",
	"U+2DDA",
	"U+2DDB",
	"U+2DDC",
	"U+2DDD",
	"U+2DDE",
	"U+2DDF",
}

var E70T54Warn = []string{
}

var E70T54Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T54Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T54In(list []string, v string) bool {
	for _, x := range list { if E70T54Lower(x) == v { return true } }
	return false
}

// E70T54Classify 分类单个令牌。
func E70T54Classify(tok string) string {
	v := E70T54Lower(tok)
	switch {
	case E70T54In(E70T54Block, v): return E70T54ClassBlock
	case E70T54In(E70T54Warn, v): return E70T54ClassWarn
	case E70T54In(E70T54Allow, v): return E70T54ClassAllow
	default: return E70T54ClassUnknown
	}
}
