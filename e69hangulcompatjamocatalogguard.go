package main

// e69hangulcompatjamocatalogguard.go —— 谚文兼容 Jamo 码位目录。
//
// 威胁模型：
//   兼容 Jamo 与现代 Jamo 码点不同但可能规范化等价，混排可绕过匹配，
//   机器字段应拒绝。纯字符查表，不用正则。

const (
	E69T28ClassBlock   = "block"
	E69T28ClassWarn    = "warn"
	E69T28ClassAllow   = "allow"
	E69T28ClassUnknown = "unknown"
)

var E69T28Block = []string{
	"U+3130",
	"U+3131",
	"U+3132",
	"U+3133",
	"U+3134",
	"U+3135",
	"U+3136",
	"U+3137",
	"U+3138",
	"U+3139",
	"U+313A",
	"U+313B",
	"U+313C",
	"U+313D",
	"U+313E",
	"U+313F",
	"U+3140",
	"U+3141",
	"U+3142",
	"U+3143",
	"U+3144",
	"U+3145",
	"U+3146",
	"U+3147",
	"U+3148",
	"U+3149",
	"U+314A",
	"U+314B",
	"U+314C",
	"U+314D",
	"U+314E",
	"U+314F",
	"U+3150",
	"U+3151",
	"U+3152",
	"U+3153",
	"U+3154",
	"U+3155",
	"U+3156",
	"U+3157",
	"U+3158",
	"U+3159",
	"U+315A",
	"U+315B",
	"U+315C",
	"U+315D",
	"U+315E",
	"U+315F",
	"U+3160",
	"U+3161",
	"U+3162",
	"U+3163",
	"U+3164",
	"U+3165",
	"U+3166",
	"U+3167",
	"U+3168",
	"U+3169",
	"U+316A",
	"U+316B",
	"U+316C",
	"U+316D",
	"U+316E",
	"U+316F",
	"U+3170",
	"U+3171",
	"U+3172",
	"U+3173",
	"U+3174",
	"U+3175",
	"U+3176",
	"U+3177",
	"U+3178",
	"U+3179",
	"U+317A",
	"U+317B",
	"U+317C",
	"U+317D",
	"U+317E",
	"U+317F",
	"U+3180",
	"U+3181",
	"U+3182",
	"U+3183",
	"U+3184",
	"U+3185",
	"U+3186",
	"U+3187",
	"U+3188",
	"U+3189",
	"U+318A",
	"U+318B",
	"U+318C",
	"U+318D",
	"U+318E",
	"U+318F",
}

var E69T28Warn = []string{
}

var E69T28Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T28Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T28In(list []string, v string) bool {
	for _, x := range list { if E69T28Lower(x) == v { return true } }
	return false
}

// E69T28Classify 分类单个令牌。
func E69T28Classify(tok string) string {
	v := E69T28Lower(tok)
	switch {
	case E69T28In(E69T28Block, v): return E69T28ClassBlock
	case E69T28In(E69T28Warn, v): return E69T28ClassWarn
	case E69T28In(E69T28Allow, v): return E69T28ClassAllow
	default: return E69T28ClassUnknown
	}
}
