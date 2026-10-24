package main

// e69tagsinvisiblecatalogguard.go —— Tags 隐形标记字符目录。
//
// 威胁模型：
//   语言标签字符 U+E0020.. 完全不可见，曾被用于构造隐形同形域与隐藏数据透传，
//   任何文本字段都应拒绝。纯字符查表，不用正则。

const (
	E69U06ClassBlock   = "block"
	E69U06ClassWarn    = "warn"
	E69U06ClassAllow   = "allow"
	E69U06ClassUnknown = "unknown"
)

var E69U06Block = []string{
	"U+E0020",
	"U+E0021",
	"U+E0022",
	"U+E0023",
	"U+E0024",
	"U+E0025",
	"U+E0026",
	"U+E0027",
	"U+E0028",
	"U+E0029",
	"U+E002A",
	"U+E002B",
	"U+E002C",
	"U+E002D",
	"U+E002E",
	"U+E002F",
	"U+E0030",
	"U+E0031",
	"U+E0032",
	"U+E0033",
	"U+E0034",
	"U+E0035",
	"U+E0036",
	"U+E0037",
	"U+E0038",
	"U+E0039",
	"U+E003A",
	"U+E003B",
	"U+E003C",
	"U+E003D",
	"U+E003E",
	"U+E003F",
	"U+E0040",
	"U+E0041",
	"U+E0042",
	"U+E0043",
	"U+E0044",
	"U+E0045",
	"U+E0046",
	"U+E0047",
	"U+E0048",
	"U+E0049",
	"U+E004A",
	"U+E004B",
	"U+E004C",
	"U+E004D",
	"U+E004E",
	"U+E004F",
	"U+E0050",
	"U+E0051",
	"U+E0052",
	"U+E0053",
	"U+E0054",
	"U+E0055",
	"U+E0056",
	"U+E0057",
	"U+E0058",
	"U+E0059",
	"U+E005A",
	"U+E005B",
	"U+E005C",
	"U+E005D",
	"U+E005E",
	"U+E005F",
	"U+E0060",
	"U+E0061",
	"U+E0062",
	"U+E0063",
	"U+E0064",
	"U+E0065",
	"U+E0066",
	"U+E0067",
	"U+E0068",
	"U+E0069",
	"U+E006A",
	"U+E006B",
	"U+E006C",
	"U+E006D",
	"U+E006E",
	"U+E006F",
	"U+E0070",
	"U+E0071",
	"U+E0072",
	"U+E0073",
	"U+E0074",
	"U+E0075",
	"U+E0076",
	"U+E0077",
	"U+E0078",
	"U+E0079",
	"U+E007A",
	"U+E007B",
	"U+E007C",
	"U+E007D",
	"U+E007E",
	"U+E007F",
}

var E69U06Warn = []string{
}

var E69U06Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69U06Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69U06In(list []string, v string) bool {
	for _, x := range list { if E69U06Lower(x) == v { return true } }
	return false
}

// E69U06Classify 分类单个令牌。
func E69U06Classify(tok string) string {
	v := E69U06Lower(tok)
	switch {
	case E69U06In(E69U06Block, v): return E69U06ClassBlock
	case E69U06In(E69U06Warn, v): return E69U06ClassWarn
	case E69U06In(E69U06Allow, v): return E69U06ClassAllow
	default: return E69U06ClassUnknown
	}
}
