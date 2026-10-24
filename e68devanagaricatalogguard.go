package main

// e68devanagaricatalogguard.go —— 天城文码位目录。
//
// 威胁模型：
//   天城文组合字符经不同规范化形成同形序列，按字形匹配的黑名单会失效，
//   应 NFKC 归一化后比较。纯字符查表，不用正则。

const (
	E68R05ClassBlock   = "block"
	E68R05ClassWarn    = "warn"
	E68R05ClassAllow   = "allow"
	E68R05ClassUnknown = "unknown"
)

var E68R05Block = []string{
}

var E68R05Warn = []string{
	"U+0900",
	"U+0901",
	"U+0902",
	"U+0903",
	"U+0904",
	"U+0905",
	"U+0906",
	"U+0907",
	"U+0908",
	"U+0909",
	"U+090A",
	"U+090B",
	"U+090C",
	"U+090D",
	"U+090E",
	"U+090F",
	"U+0910",
	"U+0911",
	"U+0912",
	"U+0913",
	"U+0914",
	"U+0915",
	"U+0916",
	"U+0917",
	"U+0918",
	"U+0919",
	"U+091A",
	"U+091B",
	"U+091C",
	"U+091D",
	"U+091E",
	"U+091F",
	"U+0920",
	"U+0921",
	"U+0922",
	"U+0923",
	"U+0924",
	"U+0925",
	"U+0926",
	"U+0927",
	"U+0928",
	"U+0929",
	"U+092A",
	"U+092B",
	"U+092C",
	"U+092D",
	"U+092E",
	"U+092F",
	"U+0930",
	"U+0931",
	"U+0932",
	"U+0933",
	"U+0934",
	"U+0935",
	"U+0936",
	"U+0937",
	"U+0938",
	"U+0939",
	"U+093A",
	"U+093B",
	"U+093C",
	"U+093D",
	"U+093E",
	"U+093F",
	"U+0940",
	"U+0941",
	"U+0942",
	"U+0943",
	"U+0944",
	"U+0945",
	"U+0946",
	"U+0947",
	"U+0948",
	"U+0949",
	"U+094A",
	"U+094B",
	"U+094C",
	"U+094D",
	"U+094E",
	"U+094F",
	"U+0950",
	"U+0951",
	"U+0952",
	"U+0953",
	"U+0954",
	"U+0955",
	"U+0956",
	"U+0957",
	"U+0958",
	"U+0959",
	"U+095A",
	"U+095B",
	"U+095C",
	"U+095D",
	"U+095E",
	"U+095F",
	"U+0960",
	"U+0961",
	"U+0962",
	"U+0963",
	"U+0964",
	"U+0965",
	"U+0966",
	"U+0967",
	"U+0968",
	"U+0969",
	"U+096A",
	"U+096B",
	"U+096C",
	"U+096D",
	"U+096E",
	"U+096F",
	"U+0970",
	"U+0971",
	"U+0972",
	"U+0973",
	"U+0974",
	"U+0975",
	"U+0976",
	"U+0977",
	"U+0978",
	"U+0979",
	"U+097A",
	"U+097B",
	"U+097C",
	"U+097D",
	"U+097E",
	"U+097F",
}

var E68R05Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R05Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R05In(list []string, v string) bool {
	for _, x := range list { if E68R05Lower(x) == v { return true } }
	return false
}

// E68R05Classify 分类单个令牌。
func E68R05Classify(tok string) string {
	v := E68R05Lower(tok)
	switch {
	case E68R05In(E68R05Block, v): return E68R05ClassBlock
	case E68R05In(E68R05Warn, v): return E68R05ClassWarn
	case E68R05In(E68R05Allow, v): return E68R05ClassAllow
	default: return E68R05ClassUnknown
	}
}
