package main

// e69combiningmarksymbolscatalogguard.go —— 组合附加记号符号码位目录。
//
// 威胁模型：
//   组合用记号（如箭头、圈）叠加在基字符上形成同形，可隐藏真实内容，
//   应 NFKC 归一化并剥离。纯字符查表，不用正则。

const (
	E69T23ClassBlock   = "block"
	E69T23ClassWarn    = "warn"
	E69T23ClassAllow   = "allow"
	E69T23ClassUnknown = "unknown"
)

var E69T23Block = []string{
}

var E69T23Warn = []string{
	"U+20D0",
	"U+20D1",
	"U+20D2",
	"U+20D3",
	"U+20D4",
	"U+20D5",
	"U+20D6",
	"U+20D7",
	"U+20D8",
	"U+20D9",
	"U+20DA",
	"U+20DB",
	"U+20DC",
	"U+20DD",
	"U+20DE",
	"U+20DF",
	"U+20E0",
	"U+20E1",
	"U+20E2",
	"U+20E3",
	"U+20E4",
	"U+20E5",
	"U+20E6",
	"U+20E7",
	"U+20E8",
	"U+20E9",
	"U+20EA",
	"U+20EB",
	"U+20EC",
	"U+20ED",
	"U+20EE",
	"U+20EF",
	"U+20F0",
	"U+20F1",
	"U+20F2",
	"U+20F3",
	"U+20F4",
	"U+20F5",
	"U+20F6",
	"U+20F7",
	"U+20F8",
	"U+20F9",
	"U+20FA",
	"U+20FB",
	"U+20FC",
	"U+20FD",
	"U+20FE",
	"U+20FF",
}

var E69T23Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T23Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T23In(list []string, v string) bool {
	for _, x := range list { if E69T23Lower(x) == v { return true } }
	return false
}

// E69T23Classify 分类单个令牌。
func E69T23Classify(tok string) string {
	v := E69T23Lower(tok)
	switch {
	case E69T23In(E69T23Block, v): return E69T23ClassBlock
	case E69T23In(E69T23Warn, v): return E69T23ClassWarn
	case E69T23In(E69T23Allow, v): return E69T23ClassAllow
	default: return E69T23ClassUnknown
	}
}
