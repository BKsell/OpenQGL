package main

// e70currencysymbolscatalogguard.go —— 货币符号码位目录。
//
// 威胁模型：
//   货币符号中 ¤ 等可替换字段符号，部分环境宽度不一致，
//   机器字段应复核。纯字符查表，不用正则。

const (
	E70T37ClassBlock   = "block"
	E70T37ClassWarn    = "warn"
	E70T37ClassAllow   = "allow"
	E70T37ClassUnknown = "unknown"
)

var E70T37Block = []string{
}

var E70T37Warn = []string{
	"U+20A0",
	"U+20A1",
	"U+20A2",
	"U+20A3",
	"U+20A4",
	"U+20A5",
	"U+20A6",
	"U+20A7",
	"U+20A8",
	"U+20A9",
	"U+20AA",
	"U+20AB",
	"U+20AC",
	"U+20AD",
	"U+20AE",
	"U+20AF",
	"U+20B0",
	"U+20B1",
	"U+20B2",
	"U+20B3",
	"U+20B4",
	"U+20B5",
	"U+20B6",
	"U+20B7",
	"U+20B8",
	"U+20B9",
	"U+20BA",
	"U+20BB",
	"U+20BC",
	"U+20BD",
	"U+20BE",
	"U+20BF",
	"U+20C0",
	"U+20C1",
	"U+20C2",
	"U+20C3",
	"U+20C4",
	"U+20C5",
	"U+20C6",
	"U+20C7",
	"U+20C8",
	"U+20C9",
	"U+20CA",
	"U+20CB",
	"U+20CC",
	"U+20CD",
	"U+20CE",
	"U+20CF",
}

var E70T37Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T37Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T37In(list []string, v string) bool {
	for _, x := range list { if E70T37Lower(x) == v { return true } }
	return false
}

// E70T37Classify 分类单个令牌。
func E70T37Classify(tok string) string {
	v := E70T37Lower(tok)
	switch {
	case E70T37In(E70T37Block, v): return E70T37ClassBlock
	case E70T37In(E70T37Warn, v): return E70T37ClassWarn
	case E70T37In(E70T37Allow, v): return E70T37ClassAllow
	default: return E70T37ClassUnknown
	}
}
