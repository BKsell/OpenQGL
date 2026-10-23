package main

// pathsequencecatalogguard.go —— 路径穿越与编码逃逸序列目录。
//
// 威胁模型：
//   归档成员名/远端路径需识别 ../、..\、UNC、Windows 设备名及百分号/超长 UTF-8 编码的点斜变体。
//   本目录按整串序列精确匹配，调用方先做归一化解码，纯字符，不用正则。

const (
	TRSClassBlock   = "block"
	TRSClassWarn    = "warn"
	TRSClassAllow   = "allow"
	TRSClassUnknown = "unknown"
)

var TRSBlock = []string{
	"../",
	"..\\",
	"....//",
	"....\\\\",
	"..%2f",
	"..%5c",
	"%2e%2e%2f",
	"%2e%2e%5c",
	"..%252f",
	"..%255c",
	"%252e%252e%252f",
	"..%c0%af",
	"..%c1%9c",
	"..%ef%bc%8f",
	"%c0%ae%c0%ae%c0%af",
	"..;/",
	"..//",
	"..///",
	"..\\\\",
	"/..",
	"\\..",
	"/../",
	"\\..\\",
	"/../../",
	"\\..\\..\\",
	"../../../",
	"..\\\\..\\\\",
	"....//....//",
	"..%2f..%2f",
	"%2e%2e/",
	".%2e/",
	"..%00/",
	"..%0d%0a",
	"\\\\unc",
	"\\\\\\\\",
	"//server",
	"c:\\",
	"C:\\",
	"C:/",
	"%5c",
	"%2f",
	"%2F",
	"%5C",
	"%c0%2f",
	"%c0%5c",
}

var TRSWarn = []string{
	"./",
	".\\",
	"/",
	"\\",
	"~",
	"%2e",
	"%2E",
	"%252e",
	"%252f",
	"%255c",
	".%2f",
	".%5c",
	"..",
	"/./",
	"/\\",
	"\\/",
	"file:",
	"file://",
	"file:///",
	"localhost",
	"127.0.0.1",
	"0.0.0.0",
	"%3a",
	"%3A",
	"%00",
	"%0a",
	"%0d",
	"%20",
	"%09",
}

var TRSAllow = []string{
	"root",
	"home",
	"var",
	"etc",
	"usr",
	"bin",
	"opt",
	"tmp",
	"users",
	"downloads",
	"documents",
	"appdata",
	"minecraft",
	"mods",
	"saves",
	"screenshots",
	"resourcepacks",
	"shaderpacks",
	"logs",
	"versions",
	"assets",
	"libraries",
	"natives",
	"config",
	"backups",
}

func TRSLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func TRSIn(list []string, v string) bool {
	for _, x := range list { if TRSLower(x) == v { return true } }
	return false
}

// TRSClassify 分类单个令牌。
func TRSClassify(tok string) string {
	v := TRSLower(tok)
	switch {
	case TRSIn(TRSBlock, v): return TRSClassBlock
	case TRSIn(TRSWarn, v): return TRSClassWarn
	case TRSIn(TRSAllow, v): return TRSClassAllow
	default: return TRSClassUnknown
	}
}
