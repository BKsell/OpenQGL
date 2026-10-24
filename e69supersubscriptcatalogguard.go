package main

// e69supersubscriptcatalogguard.go —— 上下标符号码位目录。
//
// 威胁模型：
//   上标/下标数字与字母与 ASCII 基字符同形，可绕过字母数字匹配，
//   应 NFKC 归一化。纯字符查表，不用正则。

const (
	E69T22ClassBlock   = "block"
	E69T22ClassWarn    = "warn"
	E69T22ClassAllow   = "allow"
	E69T22ClassUnknown = "unknown"
)

var E69T22Block = []string{
}

var E69T22Warn = []string{
	"U+2070",
	"U+2071",
	"U+2072",
	"U+2073",
	"U+2074",
	"U+2075",
	"U+2076",
	"U+2077",
	"U+2078",
	"U+2079",
	"U+207A",
	"U+207B",
	"U+207C",
	"U+207D",
	"U+207E",
	"U+207F",
	"U+2080",
	"U+2081",
	"U+2082",
	"U+2083",
	"U+2084",
	"U+2085",
	"U+2086",
	"U+2087",
	"U+2088",
	"U+2089",
	"U+208A",
	"U+208B",
	"U+208C",
	"U+208D",
	"U+208E",
	"U+208F",
	"U+2090",
	"U+2091",
	"U+2092",
	"U+2093",
	"U+2094",
	"U+2095",
	"U+2096",
	"U+2097",
	"U+2098",
	"U+2099",
	"U+209A",
	"U+209B",
	"U+209C",
	"U+209D",
	"U+209E",
	"U+209F",
}

var E69T22Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T22Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T22In(list []string, v string) bool {
	for _, x := range list { if E69T22Lower(x) == v { return true } }
	return false
}

// E69T22Classify 分类单个令牌。
func E69T22Classify(tok string) string {
	v := E69T22Lower(tok)
	switch {
	case E69T22In(E69T22Block, v): return E69T22ClassBlock
	case E69T22In(E69T22Warn, v): return E69T22ClassWarn
	case E69T22In(E69T22Allow, v): return E69T22ClassAllow
	default: return E69T22ClassUnknown
	}
}
