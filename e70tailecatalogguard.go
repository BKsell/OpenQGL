package main

// e70tailecatalogguard.go —— 傣仂文字码位目录。
//
// 威胁模型：
//   傣仂文在标识符/路径中无正当用途，可隐藏非预期数据，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T26ClassBlock   = "block"
	E70T26ClassWarn    = "warn"
	E70T26ClassAllow   = "allow"
	E70T26ClassUnknown = "unknown"
)

var E70T26Block = []string{
	"U+1950",
	"U+1951",
	"U+1952",
	"U+1953",
	"U+1954",
	"U+1955",
	"U+1956",
	"U+1957",
	"U+1958",
	"U+1959",
	"U+195A",
	"U+195B",
	"U+195C",
	"U+195D",
	"U+195E",
	"U+195F",
	"U+1960",
	"U+1961",
	"U+1962",
	"U+1963",
	"U+1964",
	"U+1965",
	"U+1966",
	"U+1967",
	"U+1968",
	"U+1969",
	"U+196A",
	"U+196B",
	"U+196C",
	"U+196D",
	"U+196E",
	"U+196F",
	"U+1970",
	"U+1971",
	"U+1972",
	"U+1973",
	"U+1974",
	"U+1975",
	"U+1976",
	"U+1977",
	"U+1978",
	"U+1979",
	"U+197A",
	"U+197B",
	"U+197C",
	"U+197D",
	"U+197E",
	"U+197F",
}

var E70T26Warn = []string{
}

var E70T26Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T26Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T26In(list []string, v string) bool {
	for _, x := range list { if E70T26Lower(x) == v { return true } }
	return false
}

// E70T26Classify 分类单个令牌。
func E70T26Classify(tok string) string {
	v := E70T26Lower(tok)
	switch {
	case E70T26In(E70T26Block, v): return E70T26ClassBlock
	case E70T26In(E70T26Warn, v): return E70T26ClassWarn
	case E70T26In(E70T26Allow, v): return E70T26ClassAllow
	default: return E70T26ClassUnknown
	}
}
