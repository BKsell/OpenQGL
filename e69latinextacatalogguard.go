package main

// e69latinextacatalogguard.go —— 拉丁扩展 A 码位目录。
//
// 威胁模型：
//   带附加符号拉丁字母与 ASCII 基字母同形，可仿冒英文关键字与域名，
//   应 NFKC/去附加符后比较。纯字符查表，不用正则。

const (
	E69T01ClassBlock   = "block"
	E69T01ClassWarn    = "warn"
	E69T01ClassAllow   = "allow"
	E69T01ClassUnknown = "unknown"
)

var E69T01Block = []string{
}

var E69T01Warn = []string{
	"U+0100",
	"U+0101",
	"U+0102",
	"U+0103",
	"U+0104",
	"U+0105",
	"U+0106",
	"U+0107",
	"U+0108",
	"U+0109",
	"U+010A",
	"U+010B",
	"U+010C",
	"U+010D",
	"U+010E",
	"U+010F",
	"U+0110",
	"U+0111",
	"U+0112",
	"U+0113",
	"U+0114",
	"U+0115",
	"U+0116",
	"U+0117",
	"U+0118",
	"U+0119",
	"U+011A",
	"U+011B",
	"U+011C",
	"U+011D",
	"U+011E",
	"U+011F",
	"U+0120",
	"U+0121",
	"U+0122",
	"U+0123",
	"U+0124",
	"U+0125",
	"U+0126",
	"U+0127",
	"U+0128",
	"U+0129",
	"U+012A",
	"U+012B",
	"U+012C",
	"U+012D",
	"U+012E",
	"U+012F",
	"U+0130",
	"U+0131",
	"U+0132",
	"U+0133",
	"U+0134",
	"U+0135",
	"U+0136",
	"U+0137",
	"U+0138",
	"U+0139",
	"U+013A",
	"U+013B",
	"U+013C",
	"U+013D",
	"U+013E",
	"U+013F",
	"U+0140",
	"U+0141",
	"U+0142",
	"U+0143",
	"U+0144",
	"U+0145",
	"U+0146",
	"U+0147",
	"U+0148",
	"U+0149",
	"U+014A",
	"U+014B",
	"U+014C",
	"U+014D",
	"U+014E",
	"U+014F",
	"U+0150",
	"U+0151",
	"U+0152",
	"U+0153",
	"U+0154",
	"U+0155",
	"U+0156",
	"U+0157",
	"U+0158",
	"U+0159",
	"U+015A",
	"U+015B",
	"U+015C",
	"U+015D",
	"U+015E",
	"U+015F",
	"U+0160",
	"U+0161",
	"U+0162",
	"U+0163",
	"U+0164",
	"U+0165",
	"U+0166",
	"U+0167",
	"U+0168",
	"U+0169",
	"U+016A",
	"U+016B",
	"U+016C",
	"U+016D",
	"U+016E",
	"U+016F",
	"U+0170",
	"U+0171",
	"U+0172",
	"U+0173",
	"U+0174",
	"U+0175",
	"U+0176",
	"U+0177",
	"U+0178",
	"U+0179",
	"U+017A",
	"U+017B",
	"U+017C",
	"U+017D",
	"U+017E",
	"U+017F",
}

var E69T01Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T01Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T01In(list []string, v string) bool {
	for _, x := range list { if E69T01Lower(x) == v { return true } }
	return false
}

// E69T01Classify 分类单个令牌。
func E69T01Classify(tok string) string {
	v := E69T01Lower(tok)
	switch {
	case E69T01In(E69T01Block, v): return E69T01ClassBlock
	case E69T01In(E69T01Warn, v): return E69T01ClassWarn
	case E69T01In(E69T01Allow, v): return E69T01ClassAllow
	default: return E69T01ClassUnknown
	}
}
