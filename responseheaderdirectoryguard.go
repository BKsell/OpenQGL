package main

// responseheaderdirectoryguard.go —— HTTP 响应头风险目录。
//
// 威胁模型：
//   set-cookie/location/content-disposition/transfer-encoding 等响应头被输入污染可致响应拆分、缓存投毒或开放重定向，
//   常规内容协商头放行。纯字符查表，不用正则。

const (
	RH2ClassBlock   = "block"
	RH2ClassWarn    = "warn"
	RH2ClassAllow   = "allow"
	RH2ClassUnknown = "unknown"
)

var RH2Block = []string{
	"set-cookie",
	"set-cookie2",
	"location",
	"content-disposition",
	"transfer-encoding",
	"content-length",
	"host",
	"x-forwarded-host",
	"x-forwarded-proto",
	"x-forwarded-prefix",
	"forwarded",
}

var RH2Warn = []string{
	"cache-control",
	"expires",
	"refresh",
	"link",
	"link-prefetch",
	"retry-after",
	"warning",
	"x-frame-options",
	"content-security-policy",
	"permissions-policy",
}

var RH2Allow = []string{
	"content-type",
	"accept",
	"accept-encoding",
	"accept-language",
	"user-agent",
	"referer",
	"date",
	"server",
	"etag",
	"vary",
}

func RH2Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func RH2In(list []string, v string) bool {
	for _, x := range list { if RH2Lower(x) == v { return true } }
	return false
}

// RH2Classify 分类单个令牌。
func RH2Classify(tok string) string {
	v := RH2Lower(tok)
	switch {
	case RH2In(RH2Block, v): return RH2ClassBlock
	case RH2In(RH2Warn, v): return RH2ClassWarn
	case RH2In(RH2Allow, v): return RH2ClassAllow
	default: return RH2ClassUnknown
	}
}
