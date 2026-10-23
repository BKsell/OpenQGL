package main

// charsetencodingcatalogguard.go —— 危险/歧义字符编码目录。
//
// 威胁模型：
//   UTF-7 让尖括号进入文本，CESU-8/UTF-32/ISO-2022 在浏览器与 JVM 间产生解码差异，可用于 XSS 绕过。
//   本模块维护编码别名目录，纯字符，不用正则。

const (
	CECClassBlock   = "block"
	CECClassWarn    = "warn"
	CECClassAllow   = "allow"
	CECClassUnknown = "unknown"
)

var CECBlock = []string{
	"utf-7",
	"unicode-1-1-utf-7",
	"x-unicode-1-1-utf-7",
	"cesu-8",
	"utf-32",
	"utf-32be",
	"utf-32le",
	"ucs-4",
	"iso-2022-cn",
	"iso-2022-jp",
	"iso-2022-kr",
	"iso-2022-jp-2",
	"utf-1",
	"utf-9",
	"x-utf-7",
	"csunicode11utf7",
}

var CECWarn = []string{
	"utf-16",
	"utf-16be",
	"utf-16le",
	"ucs-2",
	"iso-8859-1",
	"windows-1252",
	"gbk",
	"gb2312",
	"gb18030",
	"big5",
	"shift_jis",
	"euc-jp",
	"euc-kr",
}

var CECAllow = []string{
	"utf-8",
	"us-ascii",
	"ascii",
	"iso-8859-15",
}

func CECLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CECIn(list []string, v string) bool {
	for _, x := range list { if CECLower(x) == v { return true } }
	return false
}

// CECClassify 分类单个令牌。
func CECClassify(tok string) string {
	v := CECLower(tok)
	switch {
	case CECIn(CECBlock, v): return CECClassBlock
	case CECIn(CECWarn, v): return CECClassWarn
	case CECIn(CECAllow, v): return CECClassAllow
	default: return CECClassUnknown
	}
}
