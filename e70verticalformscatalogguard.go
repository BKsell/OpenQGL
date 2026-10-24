package main

// e70verticalformscatalogguard.go —— 竖排形式标点码位目录。
//
// 威胁模型：
//   竖排形式标点与常规标点对应但码点不同，可替换分隔符绕过匹配，
//   应 NFKC 归一化。纯字符查表，不用正则。

const (
	E70T60ClassBlock   = "block"
	E70T60ClassWarn    = "warn"
	E70T60ClassAllow   = "allow"
	E70T60ClassUnknown = "unknown"
)

var E70T60Block = []string{
}

var E70T60Warn = []string{
	"U+FE10",
	"U+FE11",
	"U+FE12",
	"U+FE13",
	"U+FE14",
	"U+FE15",
	"U+FE16",
	"U+FE17",
	"U+FE18",
	"U+FE19",
	"U+FE1A",
	"U+FE1B",
	"U+FE1C",
	"U+FE1D",
	"U+FE1E",
	"U+FE1F",
}

var E70T60Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T60Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T60In(list []string, v string) bool {
	for _, x := range list { if E70T60Lower(x) == v { return true } }
	return false
}

// E70T60Classify 分类单个令牌。
func E70T60Classify(tok string) string {
	v := E70T60Lower(tok)
	switch {
	case E70T60In(E70T60Block, v): return E70T60ClassBlock
	case E70T60In(E70T60Warn, v): return E70T60ClassWarn
	case E70T60In(E70T60Allow, v): return E70T60ClassAllow
	default: return E70T60ClassUnknown
	}
}
