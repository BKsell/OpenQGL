package main

// e70buginesecatalogguard.go —— 布吉文字码位目录。
//
// 威胁模型：
//   布吉文在机器字段无正当用途，渲染依赖专用字体，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T28ClassBlock   = "block"
	E70T28ClassWarn    = "warn"
	E70T28ClassAllow   = "allow"
	E70T28ClassUnknown = "unknown"
)

var E70T28Block = []string{
	"U+1A00",
	"U+1A01",
	"U+1A02",
	"U+1A03",
	"U+1A04",
	"U+1A05",
	"U+1A06",
	"U+1A07",
	"U+1A08",
	"U+1A09",
	"U+1A0A",
	"U+1A0B",
	"U+1A0C",
	"U+1A0D",
	"U+1A0E",
	"U+1A0F",
	"U+1A10",
	"U+1A11",
	"U+1A12",
	"U+1A13",
	"U+1A14",
	"U+1A15",
	"U+1A16",
	"U+1A17",
	"U+1A18",
	"U+1A19",
	"U+1A1A",
	"U+1A1B",
	"U+1A1C",
	"U+1A1D",
	"U+1A1E",
	"U+1A1F",
}

var E70T28Warn = []string{
}

var E70T28Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T28Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T28In(list []string, v string) bool {
	for _, x := range list { if E70T28Lower(x) == v { return true } }
	return false
}

// E70T28Classify 分类单个令牌。
func E70T28Classify(tok string) string {
	v := E70T28Lower(tok)
	switch {
	case E70T28In(E70T28Block, v): return E70T28ClassBlock
	case E70T28In(E70T28Warn, v): return E70T28ClassWarn
	case E70T28In(E70T28Allow, v): return E70T28ClassAllow
	default: return E70T28ClassUnknown
	}
}
