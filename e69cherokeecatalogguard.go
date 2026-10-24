package main

// e69cherokeecatalogguard.go —— 切罗基文字码位目录。
//
// 威胁模型：
//   切罗基字母含与拉丁大写近似的字形，且在常规字段中无正当用途，
//   标识符使用应拒绝。纯字符查表，不用正则。

const (
	E69T10ClassBlock   = "block"
	E69T10ClassWarn    = "warn"
	E69T10ClassAllow   = "allow"
	E69T10ClassUnknown = "unknown"
)

var E69T10Block = []string{
	"U+13A0",
	"U+13A1",
	"U+13A2",
	"U+13A3",
	"U+13A4",
	"U+13A5",
	"U+13A6",
	"U+13A7",
	"U+13A8",
	"U+13A9",
	"U+13AA",
	"U+13AB",
	"U+13AC",
	"U+13AD",
	"U+13AE",
	"U+13AF",
	"U+13B0",
	"U+13B1",
	"U+13B2",
	"U+13B3",
	"U+13B4",
	"U+13B5",
	"U+13B6",
	"U+13B7",
	"U+13B8",
	"U+13B9",
	"U+13BA",
	"U+13BB",
	"U+13BC",
	"U+13BD",
	"U+13BE",
	"U+13BF",
	"U+13C0",
	"U+13C1",
	"U+13C2",
	"U+13C3",
	"U+13C4",
	"U+13C5",
	"U+13C6",
	"U+13C7",
	"U+13C8",
	"U+13C9",
	"U+13CA",
	"U+13CB",
	"U+13CC",
	"U+13CD",
	"U+13CE",
	"U+13CF",
	"U+13D0",
	"U+13D1",
	"U+13D2",
	"U+13D3",
	"U+13D4",
	"U+13D5",
	"U+13D6",
	"U+13D7",
	"U+13D8",
	"U+13D9",
	"U+13DA",
	"U+13DB",
	"U+13DC",
	"U+13DD",
	"U+13DE",
	"U+13DF",
	"U+13E0",
	"U+13E1",
	"U+13E2",
	"U+13E3",
	"U+13E4",
	"U+13E5",
	"U+13E6",
	"U+13E7",
	"U+13E8",
	"U+13E9",
	"U+13EA",
	"U+13EB",
	"U+13EC",
	"U+13ED",
	"U+13EE",
	"U+13EF",
	"U+13F0",
	"U+13F1",
	"U+13F2",
	"U+13F3",
	"U+13F4",
	"U+13F5",
	"U+13F6",
	"U+13F7",
	"U+13F8",
	"U+13F9",
	"U+13FA",
	"U+13FB",
	"U+13FC",
	"U+13FD",
	"U+13FE",
	"U+13FF",
}

var E69T10Warn = []string{
}

var E69T10Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T10Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T10In(list []string, v string) bool {
	for _, x := range list { if E69T10Lower(x) == v { return true } }
	return false
}

// E69T10Classify 分类单个令牌。
func E69T10Classify(tok string) string {
	v := E69T10Lower(tok)
	switch {
	case E69T10In(E69T10Block, v): return E69T10ClassBlock
	case E69T10In(E69T10Warn, v): return E69T10ClassWarn
	case E69T10In(E69T10Allow, v): return E69T10ClassAllow
	default: return E69T10ClassUnknown
	}
}
