package main

// e69overlong2uppercatalogguard.go —— 过長两字节 UTF-8 大写百分号目录。
//
// 威胁模型：
//   %C0%AF 大写形式的过長 UTF-8 与小写等价，仅匹配一种大小写会漏报，
//   危险过長序列应阻断。纯字符查表，不用正则。

const (
	E69O2UClassBlock   = "block"
	E69O2UClassWarn    = "warn"
	E69O2UClassAllow   = "allow"
	E69O2UClassUnknown = "unknown"
)

var E69O2UBlock = []string{
	"%C0%80",
	"%C0%81",
	"%C0%82",
	"%C0%83",
	"%C0%84",
	"%C0%85",
	"%C0%86",
	"%C0%87",
	"%C0%88",
	"%C0%8A",
	"%C0%8B",
	"%C0%8C",
	"%C0%8D",
	"%C0%8E",
	"%C0%8F",
	"%C0%90",
	"%C0%91",
	"%C0%92",
	"%C0%93",
	"%C0%94",
	"%C0%95",
	"%C0%96",
	"%C0%97",
	"%C0%98",
	"%C0%99",
	"%C0%9A",
	"%C0%9B",
	"%C0%9C",
	"%C0%9D",
	"%C0%9E",
	"%C0%9F",
	"%C0%A2",
	"%C0%A7",
	"%C0%A8",
	"%C0%A9",
	"%C0%AE",
	"%C0%AF",
	"%C0%BC",
	"%C0%BD",
	"%C0%BE",
	"%C0%BF",
	"%C1%80",
	"%C1%9B",
	"%C1%9C",
	"%C1%9D",
	"%C1%A0",
	"%C1%BB",
	"%C1%BC",
	"%C1%BD",
	"%C1%BF",
}

var E69O2UWarn = []string{
	"%C0%89",
	"%C0%A0",
	"%C0%A1",
	"%C0%A3",
	"%C0%A4",
	"%C0%A5",
	"%C0%A6",
	"%C0%AA",
	"%C0%AB",
	"%C0%AC",
	"%C0%AD",
	"%C0%B0",
	"%C0%B1",
	"%C0%B2",
	"%C0%B3",
	"%C0%B4",
	"%C0%B5",
	"%C0%B6",
	"%C0%B7",
	"%C0%B8",
	"%C0%B9",
	"%C0%BA",
	"%C0%BB",
	"%C1%81",
	"%C1%82",
	"%C1%83",
	"%C1%84",
	"%C1%85",
	"%C1%86",
	"%C1%87",
	"%C1%88",
	"%C1%89",
	"%C1%8A",
	"%C1%8B",
	"%C1%8C",
	"%C1%8D",
	"%C1%8E",
	"%C1%8F",
	"%C1%90",
	"%C1%91",
	"%C1%92",
	"%C1%93",
	"%C1%94",
	"%C1%95",
	"%C1%96",
	"%C1%97",
	"%C1%98",
	"%C1%99",
	"%C1%9A",
	"%C1%9E",
	"%C1%9F",
	"%C1%A1",
	"%C1%A2",
	"%C1%A3",
	"%C1%A4",
	"%C1%A5",
	"%C1%A6",
	"%C1%A7",
	"%C1%A8",
	"%C1%A9",
	"%C1%AA",
	"%C1%AB",
	"%C1%AC",
	"%C1%AD",
	"%C1%AE",
	"%C1%AF",
	"%C1%B0",
	"%C1%B1",
	"%C1%B2",
	"%C1%B3",
	"%C1%B4",
	"%C1%B5",
	"%C1%B6",
	"%C1%B7",
	"%C1%B8",
	"%C1%B9",
	"%C1%BA",
	"%C1%BE",
}

var E69O2UAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69O2ULower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69O2UIn(list []string, v string) bool {
	for _, x := range list { if E69O2ULower(x) == v { return true } }
	return false
}

// E69O2UClassify 分类单个令牌。
func E69O2UClassify(tok string) string {
	v := E69O2ULower(tok)
	switch {
	case E69O2UIn(E69O2UBlock, v): return E69O2UClassBlock
	case E69O2UIn(E69O2UWarn, v): return E69O2UClassWarn
	case E69O2UIn(E69O2UAllow, v): return E69O2UClassAllow
	default: return E69O2UClassUnknown
	}
}
