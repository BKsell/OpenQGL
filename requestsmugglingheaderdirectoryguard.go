package main

// requestsmugglingheaderdirectoryguard.go —— HTTP 请求走私关键头目录。
//
// 威胁模型：
//   Transfer-Encoding/Content-Length/TE/Connection/Upgrade 同时出现或可被输入控制时，前后端解析差异可造成请求走私，
//   这些头只能由受控传输层设置，应用代码读到外部值应阻断。纯字符查表，不用正则。

const (
	RSMClassBlock   = "block"
	RSMClassWarn    = "warn"
	RSMClassAllow   = "allow"
	RSMClassUnknown = "unknown"
)

var RSMBlock = []string{
	"transfer-encoding",
	"content-length",
	"te",
	"connection",
	"upgrade",
	"keep-alive",
	"trailer",
}

var RSMWarn = []string{
	"expect",
	"proxy-connection",
	"x-forwarded-for",
	"forwarded",
	"via",
}

var RSMAllow = []string{
	"host",
	"date",
	"accept",
	"accept-encoding",
	"user-agent",
}

func RSMLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func RSMIn(list []string, v string) bool {
	for _, x := range list { if RSMLower(x) == v { return true } }
	return false
}

// RSMClassify 分类单个令牌。
func RSMClassify(tok string) string {
	v := RSMLower(tok)
	switch {
	case RSMIn(RSMBlock, v): return RSMClassBlock
	case RSMIn(RSMWarn, v): return RSMClassWarn
	case RSMIn(RSMAllow, v): return RSMClassAllow
	default: return RSMClassUnknown
	}
}
