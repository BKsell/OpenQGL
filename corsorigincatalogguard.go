package main

// corsorigincatalogguard.go —— CORS 来源风险目录。
//
// 威胁模型：
//   通配 *、null、file/data 来源与可信域同源混淆需阻断，内网/localhost 来源复核，明确 https 站点放行。
//   纯字符查表，不用正则。

const (
	CORClassBlock   = "block"
	CORClassWarn    = "warn"
	CORClassAllow   = "allow"
	CORClassUnknown = "unknown"
)

var CORBlock = []string{
	"*",
	"null",
	"NULL",
	"Null",
	"file://",
	"data:",
	"javascript:",
	"vbscript:",
	"about:blank",
	"blob:",
	"filesystem:",
	"chrome:",
	"chrome-extension:",
	"moz-extension:",
	"resource:",
	"ws://",
	"wss://*",
	"http://*",
	"https://*",
	"//",
	"0",
	"0.0.0.0",
}

var CORWarn = []string{
	"http://localhost",
	"http://127.0.0.1",
	"http://10.",
	"http://192.168.",
	"http://172.16.",
	"https://localhost",
	"https://127.0.0.1",
	"https://10.",
	"https://192.168.",
	"http://[::1]",
	"https://[::1]",
	"localhost",
	"127.0.0.1",
	"[::1]",
	"sandbox",
	"tmp",
	"example.com",
	"localhost.localdomain",
	"samesite",
	"samesite-none",
}

var CORAllow = []string{
	"https://example.com",
	"https://www.example.com",
	"https://api.example.com",
	"https://cdn.example.com",
	"https://login.microsoftonline.com",
	"https://accounts.google.com",
	"https://github.com",
	"https://api.github.com",
	"https://www.google.com",
	"https://secure",
	"https://trusted",
	"https://mojang.com",
	"https://www.minecraft.net",
	"https://api.minecraftservices.com",
}

func CORLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CORIn(list []string, v string) bool {
	for _, x := range list { if CORLower(x) == v { return true } }
	return false
}

// CORClassify 分类单个令牌。
func CORClassify(tok string) string {
	v := CORLower(tok)
	switch {
	case CORIn(CORBlock, v): return CORClassBlock
	case CORIn(CORWarn, v): return CORClassWarn
	case CORIn(CORAllow, v): return CORClassAllow
	default: return CORClassUnknown
	}
}
