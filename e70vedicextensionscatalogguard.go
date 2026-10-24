package main

// e70vedicextensionscatalogguard.go —— 吠陀扩展组合记号目录。
//
// 威胁模型：
//   吠陀扩展记号叠加在基字符上不占独立视觉位，可隐藏码点，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T33ClassBlock   = "block"
	E70T33ClassWarn    = "warn"
	E70T33ClassAllow   = "allow"
	E70T33ClassUnknown = "unknown"
)

var E70T33Block = []string{
	"U+1CD0",
	"U+1CD1",
	"U+1CD2",
	"U+1CD3",
	"U+1CD4",
	"U+1CD5",
	"U+1CD6",
	"U+1CD7",
	"U+1CD8",
	"U+1CD9",
	"U+1CDA",
	"U+1CDB",
	"U+1CDC",
	"U+1CDD",
	"U+1CDE",
	"U+1CDF",
	"U+1CE0",
	"U+1CE1",
	"U+1CE2",
	"U+1CE3",
	"U+1CE4",
	"U+1CE5",
	"U+1CE6",
	"U+1CE7",
	"U+1CE8",
	"U+1CE9",
	"U+1CEA",
	"U+1CEB",
	"U+1CEC",
	"U+1CED",
	"U+1CEE",
	"U+1CEF",
	"U+1CF0",
	"U+1CF1",
	"U+1CF2",
	"U+1CF3",
	"U+1CF4",
	"U+1CF5",
	"U+1CF6",
	"U+1CF7",
	"U+1CF8",
	"U+1CF9",
	"U+1CFA",
	"U+1CFB",
	"U+1CFC",
	"U+1CFD",
	"U+1CFE",
	"U+1CFF",
}

var E70T33Warn = []string{
}

var E70T33Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T33Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T33In(list []string, v string) bool {
	for _, x := range list { if E70T33Lower(x) == v { return true } }
	return false
}

// E70T33Classify 分类单个令牌。
func E70T33Classify(tok string) string {
	v := E70T33Lower(tok)
	switch {
	case E70T33In(E70T33Block, v): return E70T33ClassBlock
	case E70T33In(E70T33Warn, v): return E70T33ClassWarn
	case E70T33In(E70T33Allow, v): return E70T33ClassAllow
	default: return E70T33ClassUnknown
	}
}
