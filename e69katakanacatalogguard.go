package main

// e69katakanacatalogguard.go —— 片假名码位目录。
//
// 威胁模型：
//   片假名在机器标识符中无正当用途，全角片假名还可能与符号混淆，
//   机器字段应拒绝。纯字符查表，不用正则。

const (
	E69T26ClassBlock   = "block"
	E69T26ClassWarn    = "warn"
	E69T26ClassAllow   = "allow"
	E69T26ClassUnknown = "unknown"
)

var E69T26Block = []string{
	"U+30A0",
	"U+30A1",
	"U+30A2",
	"U+30A3",
	"U+30A4",
	"U+30A5",
	"U+30A6",
	"U+30A7",
	"U+30A8",
	"U+30A9",
	"U+30AA",
	"U+30AB",
	"U+30AC",
	"U+30AD",
	"U+30AE",
	"U+30AF",
	"U+30B0",
	"U+30B1",
	"U+30B2",
	"U+30B3",
	"U+30B4",
	"U+30B5",
	"U+30B6",
	"U+30B7",
	"U+30B8",
	"U+30B9",
	"U+30BA",
	"U+30BB",
	"U+30BC",
	"U+30BD",
	"U+30BE",
	"U+30BF",
	"U+30C0",
	"U+30C1",
	"U+30C2",
	"U+30C3",
	"U+30C4",
	"U+30C5",
	"U+30C6",
	"U+30C7",
	"U+30C8",
	"U+30C9",
	"U+30CA",
	"U+30CB",
	"U+30CC",
	"U+30CD",
	"U+30CE",
	"U+30CF",
	"U+30D0",
	"U+30D1",
	"U+30D2",
	"U+30D3",
	"U+30D4",
	"U+30D5",
	"U+30D6",
	"U+30D7",
	"U+30D8",
	"U+30D9",
	"U+30DA",
	"U+30DB",
	"U+30DC",
	"U+30DD",
	"U+30DE",
	"U+30DF",
	"U+30E0",
	"U+30E1",
	"U+30E2",
	"U+30E3",
	"U+30E4",
	"U+30E5",
	"U+30E6",
	"U+30E7",
	"U+30E8",
	"U+30E9",
	"U+30EA",
	"U+30EB",
	"U+30EC",
	"U+30ED",
	"U+30EE",
	"U+30EF",
	"U+30F0",
	"U+30F1",
	"U+30F2",
	"U+30F3",
	"U+30F4",
	"U+30F5",
	"U+30F6",
	"U+30F7",
	"U+30F8",
	"U+30F9",
	"U+30FA",
	"U+30FB",
	"U+30FC",
	"U+30FD",
	"U+30FE",
	"U+30FF",
}

var E69T26Warn = []string{
}

var E69T26Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T26Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T26In(list []string, v string) bool {
	for _, x := range list { if E69T26Lower(x) == v { return true } }
	return false
}

// E69T26Classify 分类单个令牌。
func E69T26Classify(tok string) string {
	v := E69T26Lower(tok)
	switch {
	case E69T26In(E69T26Block, v): return E69T26ClassBlock
	case E69T26In(E69T26Warn, v): return E69T26ClassWarn
	case E69T26In(E69T26Allow, v): return E69T26ClassAllow
	default: return E69T26ClassUnknown
	}
}
