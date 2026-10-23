package main

// iosatsinsecuredirectoryguard.go —— iOS ATS 例外配置目录。
//
// 威胁模型：
//   NSAllowsArbitraryLoads 或域级 NSExceptionAllowsInsecure 关闭 App Transport Security，
//   应保持 TLS1.2+ 强制。纯字符查表，不用正则。

const (
	IASClassBlock   = "block"
	IASClassWarn    = "warn"
	IASClassAllow   = "allow"
	IASClassUnknown = "unknown"
)

var IASBlock = []string{
	"nsallowsarbitraryloads",
	"nsexceptionallowsinsecure",
	"nsallowsarbitraryloadsinwebcontent",
}

var IASWarn = []string{
	"nsminimumtlsversion-1.0",
}

var IASAllow = []string{
	"tls1.2",
	"ats-default",
}

func IASLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func IASIn(list []string, v string) bool {
	for _, x := range list { if IASLower(x) == v { return true } }
	return false
}

// IASClassify 分类单个令牌。
func IASClassify(tok string) string {
	v := IASLower(tok)
	switch {
	case IASIn(IASBlock, v): return IASClassBlock
	case IASIn(IASWarn, v): return IASClassWarn
	case IASIn(IASAllow, v): return IASClassAllow
	default: return IASClassUnknown
	}
}
