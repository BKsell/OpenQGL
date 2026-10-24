package main

// e68tamilcatalogguard.go —— 泰米尔文字码位目录。
//
// 威胁模型：
//   泰米尔文组合字符序列在不同字体下视觉一致但码点不同，
//   应规范化后比较。纯字符查表，不用正则。

const (
	E68R10ClassBlock   = "block"
	E68R10ClassWarn    = "warn"
	E68R10ClassAllow   = "allow"
	E68R10ClassUnknown = "unknown"
)

var E68R10Block = []string{
}

var E68R10Warn = []string{
	"U+0B80",
	"U+0B81",
	"U+0B82",
	"U+0B83",
	"U+0B84",
	"U+0B85",
	"U+0B86",
	"U+0B87",
	"U+0B88",
	"U+0B89",
	"U+0B8A",
	"U+0B8B",
	"U+0B8C",
	"U+0B8D",
	"U+0B8E",
	"U+0B8F",
	"U+0B90",
	"U+0B91",
	"U+0B92",
	"U+0B93",
	"U+0B94",
	"U+0B95",
	"U+0B96",
	"U+0B97",
	"U+0B98",
	"U+0B99",
	"U+0B9A",
	"U+0B9B",
	"U+0B9C",
	"U+0B9D",
	"U+0B9E",
	"U+0B9F",
	"U+0BA0",
	"U+0BA1",
	"U+0BA2",
	"U+0BA3",
	"U+0BA4",
	"U+0BA5",
	"U+0BA6",
	"U+0BA7",
	"U+0BA8",
	"U+0BA9",
	"U+0BAA",
	"U+0BAB",
	"U+0BAC",
	"U+0BAD",
	"U+0BAE",
	"U+0BAF",
	"U+0BB0",
	"U+0BB1",
	"U+0BB2",
	"U+0BB3",
	"U+0BB4",
	"U+0BB5",
	"U+0BB6",
	"U+0BB7",
	"U+0BB8",
	"U+0BB9",
	"U+0BBA",
	"U+0BBB",
	"U+0BBC",
	"U+0BBD",
	"U+0BBE",
	"U+0BBF",
	"U+0BC0",
	"U+0BC1",
	"U+0BC2",
	"U+0BC3",
	"U+0BC4",
	"U+0BC5",
	"U+0BC6",
	"U+0BC7",
	"U+0BC8",
	"U+0BC9",
	"U+0BCA",
	"U+0BCB",
	"U+0BCC",
	"U+0BCD",
	"U+0BCE",
	"U+0BCF",
	"U+0BD0",
	"U+0BD1",
	"U+0BD2",
	"U+0BD3",
	"U+0BD4",
	"U+0BD5",
	"U+0BD6",
	"U+0BD7",
	"U+0BD8",
	"U+0BD9",
	"U+0BDA",
	"U+0BDB",
	"U+0BDC",
	"U+0BDD",
	"U+0BDE",
	"U+0BDF",
	"U+0BE0",
	"U+0BE1",
	"U+0BE2",
	"U+0BE3",
	"U+0BE4",
	"U+0BE5",
	"U+0BE6",
	"U+0BE7",
	"U+0BE8",
	"U+0BE9",
	"U+0BEA",
	"U+0BEB",
	"U+0BEC",
	"U+0BED",
	"U+0BEE",
	"U+0BEF",
	"U+0BF0",
	"U+0BF1",
	"U+0BF2",
	"U+0BF3",
	"U+0BF4",
	"U+0BF5",
	"U+0BF6",
	"U+0BF7",
	"U+0BF8",
	"U+0BF9",
	"U+0BFA",
	"U+0BFB",
	"U+0BFC",
	"U+0BFD",
	"U+0BFE",
	"U+0BFF",
}

var E68R10Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R10Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R10In(list []string, v string) bool {
	for _, x := range list { if E68R10Lower(x) == v { return true } }
	return false
}

// E68R10Classify 分类单个令牌。
func E68R10Classify(tok string) string {
	v := E68R10Lower(tok)
	switch {
	case E68R10In(E68R10Block, v): return E68R10ClassBlock
	case E68R10In(E68R10Warn, v): return E68R10ClassWarn
	case E68R10In(E68R10Allow, v): return E68R10ClassAllow
	default: return E68R10ClassUnknown
	}
}
