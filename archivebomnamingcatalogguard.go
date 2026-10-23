package main

// archivebomnamingcatalogguard.go —— 归档 BOM 与特殊文件名目录。
//
// 威胁模型：
//   UTF-16/UTF-8 BOM、右到左覆盖符、零宽字符、同形异义字符可伪装文件名。本目录收录特殊码点令牌，
//   纯字符查表，不用正则。

const (
	ABNClassBlock   = "block"
	ABNClassWarn    = "warn"
	ABNClassAllow   = "allow"
	ABNClassUnknown = "unknown"
)

var ABNBlock = []string{
	"\\xEF\\xBB\\xBF",
	"\\xFF\\xFE",
	"\\xFE\\xFF",
	"\\x00",
	"\\u202E",
	"\\u202A",
	"\\u202B",
	"\\u202C",
	"\\u202D",
	"%E2%80%AE",
	"%E2%80%AA",
	"%E2%80%AB",
	"%E2%80%AC",
	"%E2%80%AD",
	"\\u200B",
	"\\u200C",
	"\\u200D",
	"\\u2060",
	"\\uFEFF",
	"%E2%80%8B",
	"%E2%80%8C",
	"%E2%80%8D",
	"%E2%81%A0",
	"%EF%BB%BF",
	"%00",
	"\\u0000",
	"%C2%AD",
	"\\u00AD",
	"​",
	"‏",
	"‮",
}

var ABNWarn = []string{
	"ﬁ",
	"ﬂ",
	"ﬀ",
	"ﬃ",
	"ﬄ",
	"А",
	"а",
	"е",
	"о",
	"р",
	"с",
	"х",
	"Α",
	"α",
	"ο",
	"ν",
	"fullwidth",
	"ａ",
	"１",
	"＠",
	"％",
	"／",
	"combining",
	"é",
	"ñ",
	"ü",
	"ç",
	"ł",
	"ą",
	"ş",
	"ı",
	"İ",
}

var ABNAllow = []string{
	"a",
	"b",
	"c",
	"z",
	"A",
	"B",
	"C",
	"Z",
	"0",
	"1",
	"9",
	"-",
	"_",
	".txt",
	".png",
	".jpg",
	".jar",
	".zip",
	".json",
	".toml",
	".yml",
	".md",
}

func ABNLower(x string) string {
	return x
}

func ABNIn(list []string, v string) bool {
	for _, x := range list { if ABNLower(x) == v { return true } }
	return false
}

// ABNClassify 分类单个令牌。
func ABNClassify(tok string) string {
	v := ABNLower(tok)
	switch {
	case ABNIn(ABNBlock, v): return ABNClassBlock
	case ABNIn(ABNWarn, v): return ABNClassWarn
	case ABNIn(ABNAllow, v): return ABNClassAllow
	default: return ABNClassUnknown
	}
}
