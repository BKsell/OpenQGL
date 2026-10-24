package main

// e69copticcatalogguard.go —— 科普特文字码位目录。
//
// 威胁模型：
//   科普特字母与部分希腊大写字形近似，混排可绕过同形检测，
//   标识符使用应拒绝。纯字符查表，不用正则。

const (
	E69T16ClassBlock   = "block"
	E69T16ClassWarn    = "warn"
	E69T16ClassAllow   = "allow"
	E69T16ClassUnknown = "unknown"
)

var E69T16Block = []string{
	"U+2C80",
	"U+2C81",
	"U+2C82",
	"U+2C83",
	"U+2C84",
	"U+2C85",
	"U+2C86",
	"U+2C87",
	"U+2C88",
	"U+2C89",
	"U+2C8A",
	"U+2C8B",
	"U+2C8C",
	"U+2C8D",
	"U+2C8E",
	"U+2C8F",
	"U+2C90",
	"U+2C91",
	"U+2C92",
	"U+2C93",
	"U+2C94",
	"U+2C95",
	"U+2C96",
	"U+2C97",
	"U+2C98",
	"U+2C99",
	"U+2C9A",
	"U+2C9B",
	"U+2C9C",
	"U+2C9D",
	"U+2C9E",
	"U+2C9F",
	"U+2CA0",
	"U+2CA1",
	"U+2CA2",
	"U+2CA3",
	"U+2CA4",
	"U+2CA5",
	"U+2CA6",
	"U+2CA7",
	"U+2CA8",
	"U+2CA9",
	"U+2CAA",
	"U+2CAB",
	"U+2CAC",
	"U+2CAD",
	"U+2CAE",
	"U+2CAF",
	"U+2CB0",
	"U+2CB1",
	"U+2CB2",
	"U+2CB3",
	"U+2CB4",
	"U+2CB5",
	"U+2CB6",
	"U+2CB7",
	"U+2CB8",
	"U+2CB9",
	"U+2CBA",
	"U+2CBB",
	"U+2CBC",
	"U+2CBD",
	"U+2CBE",
	"U+2CBF",
	"U+2CC0",
	"U+2CC1",
	"U+2CC2",
	"U+2CC3",
	"U+2CC4",
	"U+2CC5",
	"U+2CC6",
	"U+2CC7",
	"U+2CC8",
	"U+2CC9",
	"U+2CCA",
	"U+2CCB",
	"U+2CCC",
	"U+2CCD",
	"U+2CCE",
	"U+2CCF",
	"U+2CD0",
	"U+2CD1",
	"U+2CD2",
	"U+2CD3",
	"U+2CD4",
	"U+2CD5",
	"U+2CD6",
	"U+2CD7",
	"U+2CD8",
	"U+2CD9",
	"U+2CDA",
	"U+2CDB",
	"U+2CDC",
	"U+2CDD",
	"U+2CDE",
	"U+2CDF",
	"U+2CE0",
	"U+2CE1",
	"U+2CE2",
	"U+2CE3",
	"U+2CE4",
	"U+2CE5",
	"U+2CE6",
	"U+2CE7",
	"U+2CE8",
	"U+2CE9",
	"U+2CEA",
	"U+2CEB",
	"U+2CEC",
	"U+2CED",
	"U+2CEE",
	"U+2CEF",
	"U+2CF0",
	"U+2CF1",
	"U+2CF2",
	"U+2CF3",
	"U+2CF4",
	"U+2CF5",
	"U+2CF6",
	"U+2CF7",
	"U+2CF8",
	"U+2CF9",
	"U+2CFA",
	"U+2CFB",
	"U+2CFC",
	"U+2CFD",
	"U+2CFE",
	"U+2CFF",
}

var E69T16Warn = []string{
}

var E69T16Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T16Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T16In(list []string, v string) bool {
	for _, x := range list { if E69T16Lower(x) == v { return true } }
	return false
}

// E69T16Classify 分类单个令牌。
func E69T16Classify(tok string) string {
	v := E69T16Lower(tok)
	switch {
	case E69T16In(E69T16Block, v): return E69T16ClassBlock
	case E69T16In(E69T16Warn, v): return E69T16ClassWarn
	case E69T16In(E69T16Allow, v): return E69T16ClassAllow
	default: return E69T16ClassUnknown
	}
}
