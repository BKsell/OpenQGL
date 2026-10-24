package main

// e70blockelementscatalogguard.go —— 方块元号码位目录。
//
// 威胁模型：
//   方块元字符用于拼接伪界面，在标识符/路径中无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T46ClassBlock   = "block"
	E70T46ClassWarn    = "warn"
	E70T46ClassAllow   = "allow"
	E70T46ClassUnknown = "unknown"
)

var E70T46Block = []string{
	"U+2580",
	"U+2581",
	"U+2582",
	"U+2583",
	"U+2584",
	"U+2585",
	"U+2586",
	"U+2587",
	"U+2588",
	"U+2589",
	"U+258A",
	"U+258B",
	"U+258C",
	"U+258D",
	"U+258E",
	"U+258F",
	"U+2590",
	"U+2591",
	"U+2592",
	"U+2593",
	"U+2594",
	"U+2595",
	"U+2596",
	"U+2597",
	"U+2598",
	"U+2599",
	"U+259A",
	"U+259B",
	"U+259C",
	"U+259D",
	"U+259E",
	"U+259F",
}

var E70T46Warn = []string{
}

var E70T46Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T46Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T46In(list []string, v string) bool {
	for _, x := range list { if E70T46Lower(x) == v { return true } }
	return false
}

// E70T46Classify 分类单个令牌。
func E70T46Classify(tok string) string {
	v := E70T46Lower(tok)
	switch {
	case E70T46In(E70T46Block, v): return E70T46ClassBlock
	case E70T46In(E70T46Warn, v): return E70T46ClassWarn
	case E70T46In(E70T46Allow, v): return E70T46ClassAllow
	default: return E70T46ClassUnknown
	}
}
