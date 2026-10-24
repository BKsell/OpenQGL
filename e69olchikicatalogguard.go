package main

// e69olchikicatalogguard.go —— 奥尔奇基文字码位目录。
//
// 威胁模型：
//   奥尔奇基为小众文字，常规字段无正当用途，缺字体时无法稳定渲染，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E69T15ClassBlock   = "block"
	E69T15ClassWarn    = "warn"
	E69T15ClassAllow   = "allow"
	E69T15ClassUnknown = "unknown"
)

var E69T15Block = []string{
	"U+1C50",
	"U+1C51",
	"U+1C52",
	"U+1C53",
	"U+1C54",
	"U+1C55",
	"U+1C56",
	"U+1C57",
	"U+1C58",
	"U+1C59",
	"U+1C5A",
	"U+1C5B",
	"U+1C5C",
	"U+1C5D",
	"U+1C5E",
	"U+1C5F",
	"U+1C60",
	"U+1C61",
	"U+1C62",
	"U+1C63",
	"U+1C64",
	"U+1C65",
	"U+1C66",
	"U+1C67",
	"U+1C68",
	"U+1C69",
	"U+1C6A",
	"U+1C6B",
	"U+1C6C",
	"U+1C6D",
	"U+1C6E",
	"U+1C6F",
	"U+1C70",
	"U+1C71",
	"U+1C72",
	"U+1C73",
	"U+1C74",
	"U+1C75",
	"U+1C76",
	"U+1C77",
	"U+1C78",
	"U+1C79",
	"U+1C7A",
	"U+1C7B",
	"U+1C7C",
	"U+1C7D",
	"U+1C7E",
	"U+1C7F",
}

var E69T15Warn = []string{
}

var E69T15Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T15Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T15In(list []string, v string) bool {
	for _, x := range list { if E69T15Lower(x) == v { return true } }
	return false
}

// E69T15Classify 分类单个令牌。
func E69T15Classify(tok string) string {
	v := E69T15Lower(tok)
	switch {
	case E69T15In(E69T15Block, v): return E69T15ClassBlock
	case E69T15In(E69T15Warn, v): return E69T15ClassWarn
	case E69T15In(E69T15Allow, v): return E69T15ClassAllow
	default: return E69T15ClassUnknown
	}
}
