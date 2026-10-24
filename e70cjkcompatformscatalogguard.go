package main

// e70cjkcompatformscatalogguard.go —— CJK 兼容形式标点码位目录。
//
// 威胁模型：
//   ︰ ﹏ 等兼容形式标点与 ASCII/常规标点视觉近似，可仿冒分隔符，
//   应 NFKC 归一化后判定。纯字符查表，不用正则。

const (
	E70T61ClassBlock   = "block"
	E70T61ClassWarn    = "warn"
	E70T61ClassAllow   = "allow"
	E70T61ClassUnknown = "unknown"
)

var E70T61Block = []string{
}

var E70T61Warn = []string{
	"U+FE30",
	"U+FE31",
	"U+FE32",
	"U+FE33",
	"U+FE34",
	"U+FE35",
	"U+FE36",
	"U+FE37",
	"U+FE38",
	"U+FE39",
	"U+FE3A",
	"U+FE3B",
	"U+FE3C",
	"U+FE3D",
	"U+FE3E",
	"U+FE3F",
	"U+FE40",
	"U+FE41",
	"U+FE42",
	"U+FE43",
	"U+FE44",
	"U+FE45",
	"U+FE46",
	"U+FE47",
	"U+FE48",
	"U+FE49",
	"U+FE4A",
	"U+FE4B",
	"U+FE4C",
	"U+FE4D",
	"U+FE4E",
	"U+FE4F",
}

var E70T61Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T61Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T61In(list []string, v string) bool {
	for _, x := range list { if E70T61Lower(x) == v { return true } }
	return false
}

// E70T61Classify 分类单个令牌。
func E70T61Classify(tok string) string {
	v := E70T61Lower(tok)
	switch {
	case E70T61In(E70T61Block, v): return E70T61ClassBlock
	case E70T61In(E70T61Warn, v): return E70T61ClassWarn
	case E70T61In(E70T61Allow, v): return E70T61ClassAllow
	default: return E70T61ClassUnknown
	}
}
