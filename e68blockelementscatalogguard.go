package main

// e68blockelementscatalogguard.go —— 方块元素码位目录。
//
// 威胁模型：
//   方块元素在终端可覆盖/遮挡既有文本，用于进度条欺骗与内容隐藏，
//   应按码点判定。纯字符查表，不用正则。

const (
	E68R32ClassBlock   = "block"
	E68R32ClassWarn    = "warn"
	E68R32ClassAllow   = "allow"
	E68R32ClassUnknown = "unknown"
)

var E68R32Block = []string{
}

var E68R32Warn = []string{
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

var E68R32Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R32Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R32In(list []string, v string) bool {
	for _, x := range list { if E68R32Lower(x) == v { return true } }
	return false
}

// E68R32Classify 分类单个令牌。
func E68R32Classify(tok string) string {
	v := E68R32Lower(tok)
	switch {
	case E68R32In(E68R32Block, v): return E68R32ClassBlock
	case E68R32In(E68R32Warn, v): return E68R32ClassWarn
	case E68R32In(E68R32Allow, v): return E68R32ClassAllow
	default: return E68R32ClassUnknown
	}
}
