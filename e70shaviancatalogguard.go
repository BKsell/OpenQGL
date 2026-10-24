package main

// e70shaviancatalogguard.go —— 萧伯纳字母平面目录。
//
// 威胁模型：
//   萧伯纳字母与拉丁音位对应但字形不同，机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70U06ClassBlock   = "block"
	E70U06ClassWarn    = "warn"
	E70U06ClassAllow   = "allow"
	E70U06ClassUnknown = "unknown"
)

var E70U06Block = []string{
	"U+10450",
	"U+10451",
	"U+10452",
	"U+10453",
	"U+10454",
	"U+10455",
	"U+10456",
	"U+10457",
	"U+10458",
	"U+10459",
	"U+1045A",
	"U+1045B",
	"U+1045C",
	"U+1045D",
	"U+1045E",
	"U+1045F",
	"U+10460",
	"U+10461",
	"U+10462",
	"U+10463",
	"U+10464",
	"U+10465",
	"U+10466",
	"U+10467",
	"U+10468",
	"U+10469",
	"U+1046A",
	"U+1046B",
	"U+1046C",
	"U+1046D",
	"U+1046E",
	"U+1046F",
	"U+10470",
	"U+10471",
	"U+10472",
	"U+10473",
	"U+10474",
	"U+10475",
	"U+10476",
	"U+10477",
	"U+10478",
	"U+10479",
	"U+1047A",
	"U+1047B",
	"U+1047C",
	"U+1047D",
	"U+1047E",
	"U+1047F",
}

var E70U06Warn = []string{
}

var E70U06Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70U06Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70U06In(list []string, v string) bool {
	for _, x := range list { if E70U06Lower(x) == v { return true } }
	return false
}

// E70U06Classify 分类单个令牌。
func E70U06Classify(tok string) string {
	v := E70U06Lower(tok)
	switch {
	case E70U06In(E70U06Block, v): return E70U06ClassBlock
	case E70U06In(E70U06Warn, v): return E70U06ClassWarn
	case E70U06In(E70U06Allow, v): return E70U06ClassAllow
	default: return E70U06ClassUnknown
	}
}
