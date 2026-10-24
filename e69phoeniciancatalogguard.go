package main

// e69phoeniciancatalogguard.go —— 腓尼基文字码位目录。
//
// 威胁模型：
//   腓尼基字母在常规机器字段无正当用途，缺字体时不可见，
//   应拒绝。纯字符查表，不用正则。

const (
	E69T42ClassBlock   = "block"
	E69T42ClassWarn    = "warn"
	E69T42ClassAllow   = "allow"
	E69T42ClassUnknown = "unknown"
)

var E69T42Block = []string{
	"U+10900",
	"U+10901",
	"U+10902",
	"U+10903",
	"U+10904",
	"U+10905",
	"U+10906",
	"U+10907",
	"U+10908",
	"U+10909",
	"U+1090A",
	"U+1090B",
	"U+1090C",
	"U+1090D",
	"U+1090E",
	"U+1090F",
	"U+10910",
	"U+10911",
	"U+10912",
	"U+10913",
	"U+10914",
	"U+10915",
	"U+10916",
	"U+10917",
	"U+10918",
	"U+10919",
	"U+1091A",
	"U+1091B",
	"U+1091C",
	"U+1091D",
	"U+1091E",
	"U+1091F",
}

var E69T42Warn = []string{
}

var E69T42Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T42Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T42In(list []string, v string) bool {
	for _, x := range list { if E69T42Lower(x) == v { return true } }
	return false
}

// E69T42Classify 分类单个令牌。
func E69T42Classify(tok string) string {
	v := E69T42Lower(tok)
	switch {
	case E69T42In(E69T42Block, v): return E69T42ClassBlock
	case E69T42In(E69T42Warn, v): return E69T42ClassWarn
	case E69T42In(E69T42Allow, v): return E69T42ClassAllow
	default: return E69T42ClassUnknown
	}
}
