package main

// e70laocatalogguard.go —— 老挝文字码位目录。
//
// 威胁模型：
//   老挝文在常规机器字段无正当用途，组合记号可隐藏载荷，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T20ClassBlock   = "block"
	E70T20ClassWarn    = "warn"
	E70T20ClassAllow   = "allow"
	E70T20ClassUnknown = "unknown"
)

var E70T20Block = []string{
	"U+0E80",
	"U+0E81",
	"U+0E82",
	"U+0E83",
	"U+0E84",
	"U+0E85",
	"U+0E86",
	"U+0E87",
	"U+0E88",
	"U+0E89",
	"U+0E8A",
	"U+0E8B",
	"U+0E8C",
	"U+0E8D",
	"U+0E8E",
	"U+0E8F",
	"U+0E90",
	"U+0E91",
	"U+0E92",
	"U+0E93",
	"U+0E94",
	"U+0E95",
	"U+0E96",
	"U+0E97",
	"U+0E98",
	"U+0E99",
	"U+0E9A",
	"U+0E9B",
	"U+0E9C",
	"U+0E9D",
	"U+0E9E",
	"U+0E9F",
	"U+0EA0",
	"U+0EA1",
	"U+0EA2",
	"U+0EA3",
	"U+0EA4",
	"U+0EA5",
	"U+0EA6",
	"U+0EA7",
	"U+0EA8",
	"U+0EA9",
	"U+0EAA",
	"U+0EAB",
	"U+0EAC",
	"U+0EAD",
	"U+0EAE",
	"U+0EAF",
	"U+0EB0",
	"U+0EB1",
	"U+0EB2",
	"U+0EB3",
	"U+0EB4",
	"U+0EB5",
	"U+0EB6",
	"U+0EB7",
	"U+0EB8",
	"U+0EB9",
	"U+0EBA",
	"U+0EBB",
	"U+0EBC",
	"U+0EBD",
	"U+0EBE",
	"U+0EBF",
	"U+0EC0",
	"U+0EC1",
	"U+0EC2",
	"U+0EC3",
	"U+0EC4",
	"U+0EC5",
	"U+0EC6",
	"U+0EC7",
	"U+0EC8",
	"U+0EC9",
	"U+0ECA",
	"U+0ECB",
	"U+0ECC",
	"U+0ECD",
	"U+0ECE",
	"U+0ECF",
	"U+0ED0",
	"U+0ED1",
	"U+0ED2",
	"U+0ED3",
	"U+0ED4",
	"U+0ED5",
	"U+0ED6",
	"U+0ED7",
	"U+0ED8",
	"U+0ED9",
	"U+0EDA",
	"U+0EDB",
	"U+0EDC",
	"U+0EDD",
	"U+0EDE",
	"U+0EDF",
	"U+0EE0",
	"U+0EE1",
	"U+0EE2",
	"U+0EE3",
	"U+0EE4",
	"U+0EE5",
	"U+0EE6",
	"U+0EE7",
	"U+0EE8",
	"U+0EE9",
	"U+0EEA",
	"U+0EEB",
	"U+0EEC",
	"U+0EED",
	"U+0EEE",
	"U+0EEF",
	"U+0EF0",
	"U+0EF1",
	"U+0EF2",
	"U+0EF3",
	"U+0EF4",
	"U+0EF5",
	"U+0EF6",
	"U+0EF7",
	"U+0EF8",
	"U+0EF9",
	"U+0EFA",
	"U+0EFB",
	"U+0EFC",
	"U+0EFD",
	"U+0EFE",
	"U+0EFF",
}

var E70T20Warn = []string{
}

var E70T20Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T20Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T20In(list []string, v string) bool {
	for _, x := range list { if E70T20Lower(x) == v { return true } }
	return false
}

// E70T20Classify 分类单个令牌。
func E70T20Classify(tok string) string {
	v := E70T20Lower(tok)
	switch {
	case E70T20In(E70T20Block, v): return E70T20ClassBlock
	case E70T20In(E70T20Warn, v): return E70T20ClassWarn
	case E70T20In(E70T20Allow, v): return E70T20ClassAllow
	default: return E70T20ClassUnknown
	}
}
