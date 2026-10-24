package main

// e69ornamentaldingbatscatalogguard.go —— 装饰性丁贝补充平面目录。
//
// 威胁模型：
//   装饰性丁贝符号在标识符/路径/命令中无正当用途，双宽且渲染不一致，
//   结构化字段应拒绝。纯字符查表，不用正则。

const (
	E69U00ClassBlock   = "block"
	E69U00ClassWarn    = "warn"
	E69U00ClassAllow   = "allow"
	E69U00ClassUnknown = "unknown"
)

var E69U00Block = []string{
	"U+1F650",
	"U+1F651",
	"U+1F652",
	"U+1F653",
	"U+1F654",
	"U+1F655",
	"U+1F656",
	"U+1F657",
	"U+1F658",
	"U+1F659",
	"U+1F65A",
	"U+1F65B",
	"U+1F65C",
	"U+1F65D",
	"U+1F65E",
	"U+1F65F",
	"U+1F660",
	"U+1F661",
	"U+1F662",
	"U+1F663",
	"U+1F664",
	"U+1F665",
	"U+1F666",
	"U+1F667",
	"U+1F668",
	"U+1F669",
	"U+1F66A",
	"U+1F66B",
	"U+1F66C",
	"U+1F66D",
	"U+1F66E",
	"U+1F66F",
	"U+1F670",
	"U+1F671",
	"U+1F672",
	"U+1F673",
	"U+1F674",
	"U+1F675",
	"U+1F676",
	"U+1F677",
	"U+1F678",
	"U+1F679",
	"U+1F67A",
	"U+1F67B",
	"U+1F67C",
	"U+1F67D",
	"U+1F67E",
	"U+1F67F",
}

var E69U00Warn = []string{
}

var E69U00Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69U00Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69U00In(list []string, v string) bool {
	for _, x := range list { if E69U00Lower(x) == v { return true } }
	return false
}

// E69U00Classify 分类单个令牌。
func E69U00Classify(tok string) string {
	v := E69U00Lower(tok)
	switch {
	case E69U00In(E69U00Block, v): return E69U00ClassBlock
	case E69U00In(E69U00Warn, v): return E69U00ClassWarn
	case E69U00In(E69U00Allow, v): return E69U00ClassAllow
	default: return E69U00ClassUnknown
	}
}
