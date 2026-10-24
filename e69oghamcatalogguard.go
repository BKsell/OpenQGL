package main

// e69oghamcatalogguard.go —— 欧甘文字码位目录。
//
// 威胁模型：
//   欧甘文字沿基线书写、缺字体时不可见，适合在日志/标识符中隐藏数据，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E69T11ClassBlock   = "block"
	E69T11ClassWarn    = "warn"
	E69T11ClassAllow   = "allow"
	E69T11ClassUnknown = "unknown"
)

var E69T11Block = []string{
	"U+1680",
	"U+1681",
	"U+1682",
	"U+1683",
	"U+1684",
	"U+1685",
	"U+1686",
	"U+1687",
	"U+1688",
	"U+1689",
	"U+168A",
	"U+168B",
	"U+168C",
	"U+168D",
	"U+168E",
	"U+168F",
	"U+1690",
	"U+1691",
	"U+1692",
	"U+1693",
	"U+1694",
	"U+1695",
	"U+1696",
	"U+1697",
	"U+1698",
	"U+1699",
	"U+169A",
	"U+169B",
	"U+169C",
	"U+169D",
	"U+169E",
	"U+169F",
	"U+16A0",
	"U+16A1",
	"U+16A2",
	"U+16A3",
	"U+16A4",
	"U+16A5",
	"U+16A6",
	"U+16A7",
	"U+16A8",
	"U+16A9",
	"U+16AA",
	"U+16AB",
	"U+16AC",
	"U+16AD",
	"U+16AE",
	"U+16AF",
	"U+16B0",
	"U+16B1",
	"U+16B2",
	"U+16B3",
	"U+16B4",
	"U+16B5",
	"U+16B6",
	"U+16B7",
	"U+16B8",
	"U+16B9",
	"U+16BA",
	"U+16BB",
	"U+16BC",
	"U+16BD",
	"U+16BE",
	"U+16BF",
	"U+16C0",
	"U+16C1",
	"U+16C2",
	"U+16C3",
	"U+16C4",
	"U+16C5",
	"U+16C6",
	"U+16C7",
	"U+16C8",
	"U+16C9",
	"U+16CA",
	"U+16CB",
	"U+16CC",
	"U+16CD",
	"U+16CE",
	"U+16CF",
	"U+16D0",
	"U+16D1",
	"U+16D2",
	"U+16D3",
	"U+16D4",
	"U+16D5",
	"U+16D6",
	"U+16D7",
	"U+16D8",
	"U+16D9",
	"U+16DA",
	"U+16DB",
	"U+16DC",
	"U+16DD",
	"U+16DE",
	"U+16DF",
	"U+16E0",
	"U+16E1",
	"U+16E2",
	"U+16E3",
	"U+16E4",
	"U+16E5",
	"U+16E6",
	"U+16E7",
	"U+16E8",
	"U+16E9",
	"U+16EA",
	"U+16EB",
	"U+16EC",
	"U+16ED",
	"U+16EE",
	"U+16EF",
	"U+16F0",
	"U+16F1",
	"U+16F2",
	"U+16F3",
	"U+16F4",
	"U+16F5",
	"U+16F6",
	"U+16F7",
	"U+16F8",
	"U+16F9",
	"U+16FA",
	"U+16FB",
	"U+16FC",
	"U+16FD",
	"U+16FE",
	"U+16FF",
}

var E69T11Warn = []string{
}

var E69T11Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T11Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T11In(list []string, v string) bool {
	for _, x := range list { if E69T11Lower(x) == v { return true } }
	return false
}

// E69T11Classify 分类单个令牌。
func E69T11Classify(tok string) string {
	v := E69T11Lower(tok)
	switch {
	case E69T11In(E69T11Block, v): return E69T11ClassBlock
	case E69T11In(E69T11Warn, v): return E69T11ClassWarn
	case E69T11In(E69T11Allow, v): return E69T11ClassAllow
	default: return E69T11ClassUnknown
	}
}
