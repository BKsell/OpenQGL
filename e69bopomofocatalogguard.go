package main

// e69bopomofocatalogguard.go —— 注音符号码位目录。
//
// 威胁模型：
//   注音符号在常规标识符中无正当用途，可承载隐藏数据，
//   应拒绝。纯字符查表，不用正则。

const (
	E69T27ClassBlock   = "block"
	E69T27ClassWarn    = "warn"
	E69T27ClassAllow   = "allow"
	E69T27ClassUnknown = "unknown"
)

var E69T27Block = []string{
	"U+3100",
	"U+3101",
	"U+3102",
	"U+3103",
	"U+3104",
	"U+3105",
	"U+3106",
	"U+3107",
	"U+3108",
	"U+3109",
	"U+310A",
	"U+310B",
	"U+310C",
	"U+310D",
	"U+310E",
	"U+310F",
	"U+3110",
	"U+3111",
	"U+3112",
	"U+3113",
	"U+3114",
	"U+3115",
	"U+3116",
	"U+3117",
	"U+3118",
	"U+3119",
	"U+311A",
	"U+311B",
	"U+311C",
	"U+311D",
	"U+311E",
	"U+311F",
	"U+3120",
	"U+3121",
	"U+3122",
	"U+3123",
	"U+3124",
	"U+3125",
	"U+3126",
	"U+3127",
	"U+3128",
	"U+3129",
	"U+312A",
	"U+312B",
	"U+312C",
	"U+312D",
	"U+312E",
	"U+312F",
}

var E69T27Warn = []string{
}

var E69T27Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T27Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T27In(list []string, v string) bool {
	for _, x := range list { if E69T27Lower(x) == v { return true } }
	return false
}

// E69T27Classify 分类单个令牌。
func E69T27Classify(tok string) string {
	v := E69T27Lower(tok)
	switch {
	case E69T27In(E69T27Block, v): return E69T27ClassBlock
	case E69T27In(E69T27Warn, v): return E69T27ClassWarn
	case E69T27In(E69T27Allow, v): return E69T27ClassAllow
	default: return E69T27ClassUnknown
	}
}
