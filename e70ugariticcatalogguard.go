package main

// e70ugariticcatalogguard.go —— 乌加里特楔形字母目录。
//
// 威胁模型：
//   乌加里特字母在常规字段无正当用途，缺字体时不可见，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70U04ClassBlock   = "block"
	E70U04ClassWarn    = "warn"
	E70U04ClassAllow   = "allow"
	E70U04ClassUnknown = "unknown"
)

var E70U04Block = []string{
	"U+10380",
	"U+10381",
	"U+10382",
	"U+10383",
	"U+10384",
	"U+10385",
	"U+10386",
	"U+10387",
	"U+10388",
	"U+10389",
	"U+1038A",
	"U+1038B",
	"U+1038C",
	"U+1038D",
	"U+1038E",
	"U+1038F",
	"U+10390",
	"U+10391",
	"U+10392",
	"U+10393",
	"U+10394",
	"U+10395",
	"U+10396",
	"U+10397",
	"U+10398",
	"U+10399",
	"U+1039A",
	"U+1039B",
	"U+1039C",
	"U+1039D",
	"U+1039E",
	"U+1039F",
}

var E70U04Warn = []string{
}

var E70U04Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70U04Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70U04In(list []string, v string) bool {
	for _, x := range list { if E70U04Lower(x) == v { return true } }
	return false
}

// E70U04Classify 分类单个令牌。
func E70U04Classify(tok string) string {
	v := E70U04Lower(tok)
	switch {
	case E70U04In(E70U04Block, v): return E70U04ClassBlock
	case E70U04In(E70U04Warn, v): return E70U04ClassWarn
	case E70U04In(E70U04Allow, v): return E70U04ClassAllow
	default: return E70U04ClassUnknown
	}
}
