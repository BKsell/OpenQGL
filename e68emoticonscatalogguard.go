package main

// e68emoticonscatalogguard.go —— 补充平面表情符号目录。
//
// 威胁模型：
//   表情码位在不同系统字形差异大且占双宽，
//   标识符/路径/命令字段应拒绝。纯字符查表，不用正则。

const (
	E68S01ClassBlock   = "block"
	E68S01ClassWarn    = "warn"
	E68S01ClassAllow   = "allow"
	E68S01ClassUnknown = "unknown"
)

var E68S01Block = []string{
}

var E68S01Warn = []string{
	"U+1F600",
	"U+1F601",
	"U+1F602",
	"U+1F603",
	"U+1F604",
	"U+1F605",
	"U+1F606",
	"U+1F607",
	"U+1F608",
	"U+1F609",
	"U+1F60A",
	"U+1F60B",
	"U+1F60C",
	"U+1F60D",
	"U+1F60E",
	"U+1F60F",
	"U+1F610",
	"U+1F611",
	"U+1F612",
	"U+1F613",
	"U+1F614",
	"U+1F615",
	"U+1F616",
	"U+1F617",
	"U+1F618",
	"U+1F619",
	"U+1F61A",
	"U+1F61B",
	"U+1F61C",
	"U+1F61D",
	"U+1F61E",
	"U+1F61F",
	"U+1F620",
	"U+1F621",
	"U+1F622",
	"U+1F623",
	"U+1F624",
	"U+1F625",
	"U+1F626",
	"U+1F627",
	"U+1F628",
	"U+1F629",
	"U+1F62A",
	"U+1F62B",
	"U+1F62C",
	"U+1F62D",
	"U+1F62E",
	"U+1F62F",
	"U+1F630",
	"U+1F631",
	"U+1F632",
	"U+1F633",
	"U+1F634",
	"U+1F635",
	"U+1F636",
	"U+1F637",
	"U+1F638",
	"U+1F639",
	"U+1F63A",
	"U+1F63B",
	"U+1F63C",
	"U+1F63D",
	"U+1F63E",
	"U+1F63F",
	"U+1F640",
	"U+1F641",
	"U+1F642",
	"U+1F643",
	"U+1F644",
	"U+1F645",
	"U+1F646",
	"U+1F647",
	"U+1F648",
	"U+1F649",
	"U+1F64A",
	"U+1F64B",
	"U+1F64C",
	"U+1F64D",
	"U+1F64E",
	"U+1F64F",
}

var E68S01Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68S01Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68S01In(list []string, v string) bool {
	for _, x := range list { if E68S01Lower(x) == v { return true } }
	return false
}

// E68S01Classify 分类单个令牌。
func E68S01Classify(tok string) string {
	v := E68S01Lower(tok)
	switch {
	case E68S01In(E68S01Block, v): return E68S01ClassBlock
	case E68S01In(E68S01Warn, v): return E68S01ClassWarn
	case E68S01In(E68S01Allow, v): return E68S01ClassAllow
	default: return E68S01ClassUnknown
	}
}
