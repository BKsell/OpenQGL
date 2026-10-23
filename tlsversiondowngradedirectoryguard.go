package main

// tlsversiondowngradedirectoryguard.go —— TLS 协议版本目录。
//
// 威胁模型：
//   SSLv2/v3、TLS1.0/1.1 存在 BEAST/POODLE/降级问题，
//   最低应 TLS1.2，推荐 1.3。纯字符查表，不用正则。

const (
	TVDClassBlock   = "block"
	TVDClassWarn    = "warn"
	TVDClassAllow   = "allow"
	TVDClassUnknown = "unknown"
)

var TVDBlock = []string{
	"sslv2",
	"sslv3",
	"tlsv1.0",
	"tlsv1",
	"tlsv1.1",
}

var TVDWarn = []string{
	"tlsv1.2",
}

var TVDAllow = []string{
	"tlsv1.3",
}

func TVDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func TVDIn(list []string, v string) bool {
	for _, x := range list { if TVDLower(x) == v { return true } }
	return false
}

// TVDClassify 分类单个令牌。
func TVDClassify(tok string) string {
	v := TVDLower(tok)
	switch {
	case TVDIn(TVDBlock, v): return TVDClassBlock
	case TVDIn(TVDWarn, v): return TVDClassWarn
	case TVDIn(TVDAllow, v): return TVDClassAllow
	default: return TVDClassUnknown
	}
}
