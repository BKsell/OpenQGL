package main

// e70lyciancatalogguard.go —— 吕基亚文字平面目录。
//
// 威胁模型：
//   吕基亚古文字罕用，可在字段中隐藏数据而不被察觉，
//   结构化字段应拒绝。纯字符查表，不用正则。

const (
	E70U01ClassBlock   = "block"
	E70U01ClassWarn    = "warn"
	E70U01ClassAllow   = "allow"
	E70U01ClassUnknown = "unknown"
)

var E70U01Block = []string{
	"U+10280",
	"U+10281",
	"U+10282",
	"U+10283",
	"U+10284",
	"U+10285",
	"U+10286",
	"U+10287",
	"U+10288",
	"U+10289",
	"U+1028A",
	"U+1028B",
	"U+1028C",
	"U+1028D",
	"U+1028E",
	"U+1028F",
	"U+10290",
	"U+10291",
	"U+10292",
	"U+10293",
	"U+10294",
	"U+10295",
	"U+10296",
	"U+10297",
	"U+10298",
	"U+10299",
	"U+1029A",
	"U+1029B",
	"U+1029C",
	"U+1029D",
	"U+1029E",
	"U+1029F",
}

var E70U01Warn = []string{
}

var E70U01Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70U01Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70U01In(list []string, v string) bool {
	for _, x := range list { if E70U01Lower(x) == v { return true } }
	return false
}

// E70U01Classify 分类单个令牌。
func E70U01Classify(tok string) string {
	v := E70U01Lower(tok)
	switch {
	case E70U01In(E70U01Block, v): return E70U01ClassBlock
	case E70U01In(E70U01Warn, v): return E70U01ClassWarn
	case E70U01In(E70U01Allow, v): return E70U01ClassAllow
	default: return E70U01ClassUnknown
	}
}
