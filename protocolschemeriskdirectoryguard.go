package main

// protocolschemeriskdirectoryguard.go —— 出向高风险协议目录。
//
// 威胁模型：
//   gopher/file/dict/ldap/tftp/jar/netdoc 等协议在 SSRF 下可打内网服务或读本地文件，
//   出向客户端只应允许 http/https。纯字符查表，不用正则。

const (
	PSRClassBlock   = "block"
	PSRClassWarn    = "warn"
	PSRClassAllow   = "allow"
	PSRClassUnknown = "unknown"
)

var PSRBlock = []string{
	"gopher",
	"file",
	"dict",
	"ldap",
	"tftp",
	"jar",
	"netdoc",
	"ftp",
}

var PSRWarn = []string{
	"ldaps",
	"ftps",
}

var PSRAllow = []string{
	"http",
	"https",
}

func PSRLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func PSRIn(list []string, v string) bool {
	for _, x := range list { if PSRLower(x) == v { return true } }
	return false
}

// PSRClassify 分类单个令牌。
func PSRClassify(tok string) string {
	v := PSRLower(tok)
	switch {
	case PSRIn(PSRBlock, v): return PSRClassBlock
	case PSRIn(PSRWarn, v): return PSRClassWarn
	case PSRIn(PSRAllow, v): return PSRClassAllow
	default: return PSRClassUnknown
	}
}
