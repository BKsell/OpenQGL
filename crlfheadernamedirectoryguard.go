package main

// crlfheadernamedirectoryguard.go —— CRLF 响应拆分敏感头目录。
//
// 威胁模型：
//   Set-Cookie/Location/Refresh 等值若允许回车换行可注入第二响应头/响应体，
//   这些头写外部值前必须拒绝 CR/LF。纯字符查表，不用正则。

const (
	CRHClassBlock   = "block"
	CRHClassWarn    = "warn"
	CRHClassAllow   = "allow"
	CRHClassUnknown = "unknown"
)

var CRHBlock = []string{
	"set-cookie",
	"location",
	"refresh",
	"x-forwarded-host",
	"link",
}

var CRHWarn = []string{
	"content-disposition",
	"warning",
	"set-cookie2",
}

var CRHAllow = []string{
	"content-type",
	"vary",
	"cache-control",
}

func CRHLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CRHIn(list []string, v string) bool {
	for _, x := range list { if CRHLower(x) == v { return true } }
	return false
}

// CRHClassify 分类单个令牌。
func CRHClassify(tok string) string {
	v := CRHLower(tok)
	switch {
	case CRHIn(CRHBlock, v): return CRHClassBlock
	case CRHIn(CRHWarn, v): return CRHClassWarn
	case CRHIn(CRHAllow, v): return CRHClassAllow
	default: return CRHClassUnknown
	}
}
