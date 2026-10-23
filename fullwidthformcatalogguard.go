package main

// fullwidthformcatalogguard.go —— 全角 ASCII 形式目录。
//
// 威胁模型：
//   U+FF01..U+FF5E 全角形式与 ASCII 标点/字母视觉等价，可混淆关键字与域名，
//   应 NFKC 归一化后再判定。纯字符查表，不用正则。

const (
	FWFClassBlock   = "block"
	FWFClassWarn    = "warn"
	FWFClassAllow   = "allow"
	FWFClassUnknown = "unknown"
)

var FWFBlock = []string{
}

var FWFWarn = []string{
	"U+FF01",
	"U+FF02",
	"U+FF03",
	"U+FF04",
	"U+FF05",
	"U+FF06",
	"U+FF07",
	"U+FF08",
	"U+FF09",
	"U+FF0A",
	"U+FF0B",
	"U+FF0C",
	"U+FF0D",
	"U+FF0E",
	"U+FF0F",
	"U+FF10",
	"U+FF11",
	"U+FF12",
	"U+FF13",
	"U+FF14",
	"U+FF15",
	"U+FF16",
	"U+FF17",
	"U+FF18",
	"U+FF19",
	"U+FF1A",
	"U+FF1B",
	"U+FF1C",
	"U+FF1D",
	"U+FF1E",
	"U+FF1F",
	"U+FF20",
	"U+FF21",
	"U+FF22",
	"U+FF23",
	"U+FF24",
	"U+FF25",
	"U+FF26",
	"U+FF27",
	"U+FF28",
	"U+FF29",
	"U+FF2A",
	"U+FF2B",
	"U+FF2C",
	"U+FF2D",
	"U+FF2E",
	"U+FF2F",
	"U+FF30",
	"U+FF31",
	"U+FF32",
	"U+FF33",
	"U+FF34",
	"U+FF35",
	"U+FF36",
	"U+FF37",
	"U+FF38",
	"U+FF39",
	"U+FF3A",
	"U+FF3B",
	"U+FF3C",
	"U+FF3D",
	"U+FF3E",
	"U+FF3F",
	"U+FF40",
	"U+FF41",
	"U+FF42",
	"U+FF43",
	"U+FF44",
	"U+FF45",
	"U+FF46",
	"U+FF47",
	"U+FF48",
	"U+FF49",
	"U+FF4A",
	"U+FF4B",
	"U+FF4C",
	"U+FF4D",
	"U+FF4E",
	"U+FF4F",
	"U+FF50",
	"U+FF51",
	"U+FF52",
	"U+FF53",
	"U+FF54",
	"U+FF55",
	"U+FF56",
	"U+FF57",
	"U+FF58",
	"U+FF59",
	"U+FF5A",
	"U+FF5B",
	"U+FF5C",
	"U+FF5D",
	"U+FF5E",
}

var FWFAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func FWFLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func FWFIn(list []string, v string) bool {
	for _, x := range list { if FWFLower(x) == v { return true } }
	return false
}

// FWFClassify 分类单个令牌。
func FWFClassify(tok string) string {
	v := FWFLower(tok)
	switch {
	case FWFIn(FWFBlock, v): return FWFClassBlock
	case FWFIn(FWFWarn, v): return FWFClassWarn
	case FWFIn(FWFAllow, v): return FWFClassAllow
	default: return FWFClassUnknown
	}
}
