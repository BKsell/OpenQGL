package main

// e70sundanesecatalogguard.go —— 巽他文字码位目录。
//
// 威胁模型：
//   巽他文在常规机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T30ClassBlock   = "block"
	E70T30ClassWarn    = "warn"
	E70T30ClassAllow   = "allow"
	E70T30ClassUnknown = "unknown"
)

var E70T30Block = []string{
	"U+1B80",
	"U+1B81",
	"U+1B82",
	"U+1B83",
	"U+1B84",
	"U+1B85",
	"U+1B86",
	"U+1B87",
	"U+1B88",
	"U+1B89",
	"U+1B8A",
	"U+1B8B",
	"U+1B8C",
	"U+1B8D",
	"U+1B8E",
	"U+1B8F",
	"U+1B90",
	"U+1B91",
	"U+1B92",
	"U+1B93",
	"U+1B94",
	"U+1B95",
	"U+1B96",
	"U+1B97",
	"U+1B98",
	"U+1B99",
	"U+1B9A",
	"U+1B9B",
	"U+1B9C",
	"U+1B9D",
	"U+1B9E",
	"U+1B9F",
	"U+1BA0",
	"U+1BA1",
	"U+1BA2",
	"U+1BA3",
	"U+1BA4",
	"U+1BA5",
	"U+1BA6",
	"U+1BA7",
	"U+1BA8",
	"U+1BA9",
	"U+1BAA",
	"U+1BAB",
	"U+1BAC",
	"U+1BAD",
	"U+1BAE",
	"U+1BAF",
	"U+1BB0",
	"U+1BB1",
	"U+1BB2",
	"U+1BB3",
	"U+1BB4",
	"U+1BB5",
	"U+1BB6",
	"U+1BB7",
	"U+1BB8",
	"U+1BB9",
	"U+1BBA",
	"U+1BBB",
	"U+1BBC",
	"U+1BBD",
	"U+1BBE",
	"U+1BBF",
}

var E70T30Warn = []string{
}

var E70T30Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T30Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T30In(list []string, v string) bool {
	for _, x := range list { if E70T30Lower(x) == v { return true } }
	return false
}

// E70T30Classify 分类单个令牌。
func E70T30Classify(tok string) string {
	v := E70T30Lower(tok)
	switch {
	case E70T30In(E70T30Block, v): return E70T30ClassBlock
	case E70T30In(E70T30Warn, v): return E70T30ClassWarn
	case E70T30In(E70T30Allow, v): return E70T30ClassAllow
	default: return E70T30ClassUnknown
	}
}
