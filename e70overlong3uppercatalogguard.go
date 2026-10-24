package main

// e70overlong3uppercatalogguard.go —— 过長三字节 UTF-8 大写目录。
//
// 威胁模型：
//   %E0%80%AF 大写过長三字节与小写等价，仅匹配一种大小写会漏报，
//   危险过長序列应阻断。纯字符查表，不用正则。

const (
	E70O3UClassBlock   = "block"
	E70O3UClassWarn    = "warn"
	E70O3UClassAllow   = "allow"
	E70O3UClassUnknown = "unknown"
)

var E70O3UBlock = []string{
	"%E0%80%80",
	"%E0%80%81",
	"%E0%80%82",
	"%E0%80%83",
	"%E0%80%84",
	"%E0%80%85",
	"%E0%80%86",
	"%E0%80%87",
	"%E0%80%88",
	"%E0%80%8A",
	"%E0%80%8B",
	"%E0%80%8C",
	"%E0%80%8D",
	"%E0%80%8E",
	"%E0%80%8F",
	"%E0%80%90",
	"%E0%80%91",
	"%E0%80%92",
	"%E0%80%93",
	"%E0%80%94",
	"%E0%80%95",
	"%E0%80%96",
	"%E0%80%97",
	"%E0%80%98",
	"%E0%80%99",
	"%E0%80%9A",
	"%E0%80%9B",
	"%E0%80%9C",
	"%E0%80%9D",
	"%E0%80%9E",
	"%E0%80%9F",
	"%E0%80%A2",
	"%E0%80%A7",
	"%E0%80%A8",
	"%E0%80%A9",
	"%E0%80%AE",
	"%E0%80%AF",
	"%E0%80%BC",
	"%E0%80%BD",
	"%E0%80%BE",
	"%E0%80%BF",
	"%E0%80%C0",
	"%E0%80%DB",
	"%E0%80%DC",
	"%E0%80%DD",
	"%E0%80%E0",
	"%E0%80%FB",
	"%E0%80%FC",
	"%E0%80%FD",
	"%E0%80%FF",
}

var E70O3UWarn = []string{
	"%E0%80%89",
	"%E0%80%A0",
	"%E0%80%A1",
	"%E0%80%A3",
	"%E0%80%A4",
	"%E0%80%A5",
	"%E0%80%A6",
	"%E0%80%AA",
	"%E0%80%AB",
	"%E0%80%AC",
	"%E0%80%AD",
	"%E0%80%B0",
	"%E0%80%B1",
	"%E0%80%B2",
	"%E0%80%B3",
	"%E0%80%B4",
	"%E0%80%B5",
	"%E0%80%B6",
	"%E0%80%B7",
	"%E0%80%B8",
	"%E0%80%B9",
	"%E0%80%BA",
	"%E0%80%BB",
	"%E0%80%C1",
	"%E0%80%C2",
	"%E0%80%C3",
	"%E0%80%C4",
	"%E0%80%C5",
	"%E0%80%C6",
	"%E0%80%C7",
	"%E0%80%C8",
	"%E0%80%C9",
	"%E0%80%CA",
	"%E0%80%CB",
	"%E0%80%CC",
	"%E0%80%CD",
	"%E0%80%CE",
	"%E0%80%CF",
	"%E0%80%D0",
	"%E0%80%D1",
	"%E0%80%D2",
	"%E0%80%D3",
	"%E0%80%D4",
	"%E0%80%D5",
	"%E0%80%D6",
	"%E0%80%D7",
	"%E0%80%D8",
	"%E0%80%D9",
	"%E0%80%DA",
	"%E0%80%DE",
	"%E0%80%DF",
	"%E0%80%E1",
	"%E0%80%E2",
	"%E0%80%E3",
	"%E0%80%E4",
	"%E0%80%E5",
	"%E0%80%E6",
	"%E0%80%E7",
	"%E0%80%E8",
	"%E0%80%E9",
	"%E0%80%EA",
	"%E0%80%EB",
	"%E0%80%EC",
	"%E0%80%ED",
	"%E0%80%EE",
	"%E0%80%EF",
	"%E0%80%F0",
	"%E0%80%F1",
	"%E0%80%F2",
	"%E0%80%F3",
	"%E0%80%F4",
	"%E0%80%F5",
	"%E0%80%F6",
	"%E0%80%F7",
	"%E0%80%F8",
	"%E0%80%F9",
	"%E0%80%FA",
	"%E0%80%FE",
}

var E70O3UAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70O3ULower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70O3UIn(list []string, v string) bool {
	for _, x := range list { if E70O3ULower(x) == v { return true } }
	return false
}

// E70O3UClassify 分类单个令牌。
func E70O3UClassify(tok string) string {
	v := E70O3ULower(tok)
	switch {
	case E70O3UIn(E70O3UBlock, v): return E70O3UClassBlock
	case E70O3UIn(E70O3UWarn, v): return E70O3UClassWarn
	case E70O3UIn(E70O3UAllow, v): return E70O3UClassAllow
	default: return E70O3UClassUnknown
	}
}
