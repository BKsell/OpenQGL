package main

// e69cjkradicalssuppcatalogguard.go —— CJK 部首补充码位目录。
//
// 威胁模型：
//   CJK 部首补充字符与常规汉字相似但码点不同，可做关键字替换绕过，
//   机器字段应拒绝。纯字符查表，不用正则。

const (
	E69T19ClassBlock   = "block"
	E69T19ClassWarn    = "warn"
	E69T19ClassAllow   = "allow"
	E69T19ClassUnknown = "unknown"
)

var E69T19Block = []string{
	"U+2E80",
	"U+2E81",
	"U+2E82",
	"U+2E83",
	"U+2E84",
	"U+2E85",
	"U+2E86",
	"U+2E87",
	"U+2E88",
	"U+2E89",
	"U+2E8A",
	"U+2E8B",
	"U+2E8C",
	"U+2E8D",
	"U+2E8E",
	"U+2E8F",
	"U+2E90",
	"U+2E91",
	"U+2E92",
	"U+2E93",
	"U+2E94",
	"U+2E95",
	"U+2E96",
	"U+2E97",
	"U+2E98",
	"U+2E99",
	"U+2E9A",
	"U+2E9B",
	"U+2E9C",
	"U+2E9D",
	"U+2E9E",
	"U+2E9F",
	"U+2EA0",
	"U+2EA1",
	"U+2EA2",
	"U+2EA3",
	"U+2EA4",
	"U+2EA5",
	"U+2EA6",
	"U+2EA7",
	"U+2EA8",
	"U+2EA9",
	"U+2EAA",
	"U+2EAB",
	"U+2EAC",
	"U+2EAD",
	"U+2EAE",
	"U+2EAF",
	"U+2EB0",
	"U+2EB1",
	"U+2EB2",
	"U+2EB3",
	"U+2EB4",
	"U+2EB5",
	"U+2EB6",
	"U+2EB7",
	"U+2EB8",
	"U+2EB9",
	"U+2EBA",
	"U+2EBB",
	"U+2EBC",
	"U+2EBD",
	"U+2EBE",
	"U+2EBF",
	"U+2EC0",
	"U+2EC1",
	"U+2EC2",
	"U+2EC3",
	"U+2EC4",
	"U+2EC5",
	"U+2EC6",
	"U+2EC7",
	"U+2EC8",
	"U+2EC9",
	"U+2ECA",
	"U+2ECB",
	"U+2ECC",
	"U+2ECD",
	"U+2ECE",
	"U+2ECF",
	"U+2ED0",
	"U+2ED1",
	"U+2ED2",
	"U+2ED3",
	"U+2ED4",
	"U+2ED5",
	"U+2ED6",
	"U+2ED7",
	"U+2ED8",
	"U+2ED9",
	"U+2EDA",
	"U+2EDB",
	"U+2EDC",
	"U+2EDD",
	"U+2EDE",
	"U+2EDF",
	"U+2EE0",
	"U+2EE1",
	"U+2EE2",
	"U+2EE3",
	"U+2EE4",
	"U+2EE5",
	"U+2EE6",
	"U+2EE7",
	"U+2EE8",
	"U+2EE9",
	"U+2EEA",
	"U+2EEB",
	"U+2EEC",
	"U+2EED",
	"U+2EEE",
	"U+2EEF",
	"U+2EF0",
	"U+2EF1",
	"U+2EF2",
	"U+2EF3",
	"U+2EF4",
	"U+2EF5",
	"U+2EF6",
	"U+2EF7",
	"U+2EF8",
	"U+2EF9",
	"U+2EFA",
	"U+2EFB",
	"U+2EFC",
	"U+2EFD",
	"U+2EFE",
	"U+2EFF",
}

var E69T19Warn = []string{
}

var E69T19Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T19Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T19In(list []string, v string) bool {
	for _, x := range list { if E69T19Lower(x) == v { return true } }
	return false
}

// E69T19Classify 分类单个令牌。
func E69T19Classify(tok string) string {
	v := E69T19Lower(tok)
	switch {
	case E69T19In(E69T19Block, v): return E69T19ClassBlock
	case E69T19In(E69T19Warn, v): return E69T19ClassWarn
	case E69T19In(E69T19Allow, v): return E69T19ClassAllow
	default: return E69T19ClassUnknown
	}
}
