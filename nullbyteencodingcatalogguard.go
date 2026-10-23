package main

// nullbyteencodingcatalogguard.go —— 空字节与危险编码目录。
//
// 威胁模型：
//   %00/\x00/超长编码空字节可截断扩展名/路径检查，配合双重编码绕过。本目录收录空字节与危险百分号编码，
//   纯字符查表，调用方负责解码，不用正则。

const (
	NLBClassBlock   = "block"
	NLBClassWarn    = "warn"
	NLBClassAllow   = "allow"
	NLBClassUnknown = "unknown"
)

var NLBBlock = []string{
	"%00",
	"%0A",
	"%0D",
	"%0a",
	"%0d",
	"\\x00",
	"\\u0000",
	"&#0;",
	"&#00;",
	"&#x0;",
	"&0;",
	"%2500",
	"%252f00",
	"%c0%80",
	"%c0%00",
	"%e0%80%80",
	"%f0%80%80%80",
	"%f8%80%80%80%80",
	"%00.jpg",
	"%00.png",
	"%00.jsp",
	"%00.txt",
	"%00%2e",
	"file%00",
	"name%00",
	"..%00",
	"%252500",
	"%25%30%30",
	"%u0000",
	"%ufffd",
	"0x00",
	"\\0",
	"NUL",
	"nullbyte",
}

var NLBWarn = []string{
	"%01",
	"%02",
	"%03",
	"%04",
	"%05",
	"%06",
	"%07",
	"%08",
	"%0b",
	"%0c",
	"%0e",
	"%0f",
	"%10",
	"%1f",
	"%7f",
	"%80",
	"%ff",
	"%fe",
	"%c0",
	"%c1",
	"%ed",
	"%a0",
	"%bf",
	"%25",
	"%252f",
	"%255c",
	"%252e",
	"double-encoded",
	"overlong",
	"surrogate",
	"replacement",
}

var NLBAllow = []string{
	"%20",
	"%21",
	"%23",
	"%2d",
	"%2e",
	"%30",
	"%39",
	"%41",
	"%5a",
	"%61",
	"%7a",
	"%7e",
	"utf-8",
	"ascii",
	"normal",
	"safe",
}

func NLBLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func NLBIn(list []string, v string) bool {
	for _, x := range list { if NLBLower(x) == v { return true } }
	return false
}

// NLBClassify 分类单个令牌。
func NLBClassify(tok string) string {
	v := NLBLower(tok)
	switch {
	case NLBIn(NLBBlock, v): return NLBClassBlock
	case NLBIn(NLBWarn, v): return NLBClassWarn
	case NLBIn(NLBAllow, v): return NLBClassAllow
	default: return NLBClassUnknown
	}
}
