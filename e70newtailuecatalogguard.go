package main

// e70newtailuecatalogguard.go —— 新傣仂文字码位目录。
//
// 威胁模型：
//   新傣仂文罕用，在常规机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T27ClassBlock   = "block"
	E70T27ClassWarn    = "warn"
	E70T27ClassAllow   = "allow"
	E70T27ClassUnknown = "unknown"
)

var E70T27Block = []string{
	"U+1980",
	"U+1981",
	"U+1982",
	"U+1983",
	"U+1984",
	"U+1985",
	"U+1986",
	"U+1987",
	"U+1988",
	"U+1989",
	"U+198A",
	"U+198B",
	"U+198C",
	"U+198D",
	"U+198E",
	"U+198F",
	"U+1990",
	"U+1991",
	"U+1992",
	"U+1993",
	"U+1994",
	"U+1995",
	"U+1996",
	"U+1997",
	"U+1998",
	"U+1999",
	"U+199A",
	"U+199B",
	"U+199C",
	"U+199D",
	"U+199E",
	"U+199F",
	"U+19A0",
	"U+19A1",
	"U+19A2",
	"U+19A3",
	"U+19A4",
	"U+19A5",
	"U+19A6",
	"U+19A7",
	"U+19A8",
	"U+19A9",
	"U+19AA",
	"U+19AB",
	"U+19AC",
	"U+19AD",
	"U+19AE",
	"U+19AF",
	"U+19B0",
	"U+19B1",
	"U+19B2",
	"U+19B3",
	"U+19B4",
	"U+19B5",
	"U+19B6",
	"U+19B7",
	"U+19B8",
	"U+19B9",
	"U+19BA",
	"U+19BB",
	"U+19BC",
	"U+19BD",
	"U+19BE",
	"U+19BF",
	"U+19C0",
	"U+19C1",
	"U+19C2",
	"U+19C3",
	"U+19C4",
	"U+19C5",
	"U+19C6",
	"U+19C7",
	"U+19C8",
	"U+19C9",
	"U+19CA",
	"U+19CB",
	"U+19CC",
	"U+19CD",
	"U+19CE",
	"U+19CF",
	"U+19D0",
	"U+19D1",
	"U+19D2",
	"U+19D3",
	"U+19D4",
	"U+19D5",
	"U+19D6",
	"U+19D7",
	"U+19D8",
	"U+19D9",
	"U+19DA",
	"U+19DB",
	"U+19DC",
	"U+19DD",
	"U+19DE",
	"U+19DF",
}

var E70T27Warn = []string{
}

var E70T27Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T27Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T27In(list []string, v string) bool {
	for _, x := range list { if E70T27Lower(x) == v { return true } }
	return false
}

// E70T27Classify 分类单个令牌。
func E70T27Classify(tok string) string {
	v := E70T27Lower(tok)
	switch {
	case E70T27In(E70T27Block, v): return E70T27ClassBlock
	case E70T27In(E70T27Warn, v): return E70T27ClassWarn
	case E70T27In(E70T27Allow, v): return E70T27ClassAllow
	default: return E70T27ClassUnknown
	}
}
