package main

// csrfheadernamedirectoryguard.go —— CSRF 自定义请求头可信度目录。
//
// 威胁模型：
//   仅靠 X-Requested-With 不能防 CSRF（可被部分跨域形态伪造），自定义头须配合预检与令牌，
//   双提交令牌头才是校验依据。纯字符查表，不用正则。

const (
	CFHClassBlock   = "block"
	CFHClassWarn    = "warn"
	CFHClassAllow   = "allow"
	CFHClassUnknown = "unknown"
)

var CFHBlock = []string{
	"x-requested-with",
	"x-xsrf-token",
}

var CFHWarn = []string{
	"origin",
	"referer",
}

var CFHAllow = []string{
	"x-csrf-token",
	"x-csrf-header",
	"double-submit",
}

func CFHLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CFHIn(list []string, v string) bool {
	for _, x := range list { if CFHLower(x) == v { return true } }
	return false
}

// CFHClassify 分类单个令牌。
func CFHClassify(tok string) string {
	v := CFHLower(tok)
	switch {
	case CFHIn(CFHBlock, v): return CFHClassBlock
	case CFHIn(CFHWarn, v): return CFHClassWarn
	case CFHIn(CFHAllow, v): return CFHClassAllow
	default: return CFHClassUnknown
	}
}
