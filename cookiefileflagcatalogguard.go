package main

// cookiefileflagcatalogguard.go —— Cookie 文件标志与属性风险目录。
//
// 威胁模型：
//   Cookie 缺少 HttpOnly/Secure/SameSite 或带 __Host- 前缀违规需复核，逐属性精确匹配，纯字符，不用正则。

const (
	CFLClassBlock   = "block"
	CFLClassWarn    = "warn"
	CFLClassAllow   = "allow"
	CFLClassUnknown = "unknown"
)

var CFLBlock = []string{
	"SameSite=None",
}

var CFLWarn = []string{
	"Domain",
	"Path",
	"Expires",
	"Max-Age",
	"Persistent",
	"SameSite=Lax",
	"SameSite",
	"SameSite=Default",
	"Priority",
	"SameParty",
	"Partitioned",
}

var CFLAllow = []string{
	"HttpOnly",
	"Secure",
	"SameSite=Strict",
	"Lax",
	"Strict",
	"None",
	"__Host-",
	"__Secure-",
	"Session",
	"Set-Cookie",
	"Cookie",
	"name",
	"value",
	"delete",
	"clear",
	"remove",
}

func CFLLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CFLIn(list []string, v string) bool {
	for _, x := range list { if CFLLower(x) == v { return true } }
	return false
}

// CFLClassify 分类单个令牌。
func CFLClassify(tok string) string {
	v := CFLLower(tok)
	switch {
	case CFLIn(CFLBlock, v): return CFLClassBlock
	case CFLIn(CFLWarn, v): return CFLClassWarn
	case CFLIn(CFLAllow, v): return CFLClassAllow
	default: return CFLClassUnknown
	}
}
