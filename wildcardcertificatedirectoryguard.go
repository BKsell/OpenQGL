package main

// wildcardcertificatedirectoryguard.go —— 通配证书范围目录。
//
// 威胁模型：
//   *.com/*.net 这类顶级通配与裸 * 等于为任意域背书，
//   证书应限定到具体主机或最小层级通配。纯字符查表，不用正则。

const (
	WCRClassBlock   = "block"
	WCRClassWarn    = "warn"
	WCRClassAllow   = "allow"
	WCRClassUnknown = "unknown"
)

var WCRBlock = []string{
	"*",
	"*.com",
	"*.net",
	"*.org",
	"*.co.uk",
	"*.com.cn",
}

var WCRWarn = []string{
	"*.co",
	"*.io",
}

var WCRAllow = []string{
	"leaf-san",
	"exact-host",
}

func WCRLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func WCRIn(list []string, v string) bool {
	for _, x := range list { if WCRLower(x) == v { return true } }
	return false
}

// WCRClassify 分类单个令牌。
func WCRClassify(tok string) string {
	v := WCRLower(tok)
	switch {
	case WCRIn(WCRBlock, v): return WCRClassBlock
	case WCRIn(WCRWarn, v): return WCRClassWarn
	case WCRIn(WCRAllow, v): return WCRClassAllow
	default: return WCRClassUnknown
	}
}
