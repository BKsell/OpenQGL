package main

// tagspecialcodepointcatalogguard.go —— Tag 特殊字符目录。
//
// 威胁模型：
//   U+E0001..E007F 语言标签区字符不可见却参与比较，被用于标签字符钓鱼与同形攻击，
//   应直接拒绝。纯字符查表，不用正则。

const (
	TSPClassBlock   = "block"
	TSPClassWarn    = "warn"
	TSPClassAllow   = "allow"
	TSPClassUnknown = "unknown"
)

var TSPBlock = []string{
	"U+E0001",
	"U+E0002",
	"U+E0003",
	"U+E0004",
	"U+E0005",
	"U+E0006",
	"U+E0007",
	"U+E0008",
	"U+E0009",
	"U+E000A",
	"U+E000B",
	"U+E000C",
	"U+E000D",
	"U+E000E",
	"U+E000F",
	"U+E0010",
	"U+E0011",
	"U+E0012",
	"U+E0013",
	"U+E0014",
	"U+E0015",
	"U+E0016",
	"U+E0017",
	"U+E0018",
	"U+E0019",
	"U+E001A",
	"U+E001B",
	"U+E001C",
	"U+E001D",
	"U+E001E",
	"U+E001F",
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

var TSPWarn = []string{
}

var TSPAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func TSPLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func TSPIn(list []string, v string) bool {
	for _, x := range list { if TSPLower(x) == v { return true } }
	return false
}

// TSPClassify 分类单个令牌。
func TSPClassify(tok string) string {
	v := TSPLower(tok)
	switch {
	case TSPIn(TSPBlock, v): return TSPClassBlock
	case TSPIn(TSPWarn, v): return TSPClassWarn
	case TSPIn(TSPAllow, v): return TSPClassAllow
	default: return TSPClassUnknown
	}
}
