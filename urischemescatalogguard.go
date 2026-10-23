package main

// urischemescatalogguard.go —— URI Scheme 风险目录。
//
// 威胁模型：
//   深链、重定向、外呼依赖 scheme 白名单。file/jar/netdoc 可读本地，javascript/data 注入脚本，gopher/dict
//   扩大 SSRF。本模块判定单个 scheme 名，纯字符，不用正则。

const (
	USCClassBlock   = "block"
	USCClassWarn    = "warn"
	USCClassAllow   = "allow"
	USCClassUnknown = "unknown"
)

var USCBlock = []string{
	"file",
	"jar",
	"netdoc",
	"docbase",
	"javascript",
	"vbscript",
	"data",
	"gopher",
	"dict",
	"ldap",
	"rmi",
	"iiop",
	"corbaname",
	"jndi",
	"class",
	"about",
	"blob",
	"filesystem",
	"intent",
	"ms-msdt",
	"search-ms",
}

var USCWarn = []string{
	"ftp",
	"ftps",
	"mailto",
	"tel",
	"sms",
	"geo",
	"stun",
	"turn",
	"stuns",
	"turns",
	"ws",
}

var USCAllow = []string{
	"http",
	"https",
	"wss",
}

func USCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func USCIn(list []string, v string) bool {
	for _, x := range list { if USCLower(x) == v { return true } }
	return false
}

// USCClassify 分类单个令牌。
func USCClassify(tok string) string {
	v := USCLower(tok)
	switch {
	case USCIn(USCBlock, v): return USCClassBlock
	case USCIn(USCWarn, v): return USCClassWarn
	case USCIn(USCAllow, v): return USCClassAllow
	default: return USCClassUnknown
	}
}
