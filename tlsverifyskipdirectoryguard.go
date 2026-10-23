package main

// tlsverifyskipdirectoryguard.go —— TLS 跳过校验开关目录。
//
// 威胁模型：
//   InsecureSkipVerify、verify=false、关闭客户端证书校验直接打开中间人，
//   应完整校验证书链与主机名。纯字符查表，不用正则。

const (
	TCAClassBlock   = "block"
	TCAClassWarn    = "warn"
	TCAClassAllow   = "allow"
	TCAClassUnknown = "unknown"
)

var TCABlock = []string{
	"insecureskipverify",
	"verify=false",
	"skip-verify",
	"trust-all",
}

var TCAWarn = []string{
	"optional-client-cert",
}

var TCAAllow = []string{
	"verify-full",
}

func TCALower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func TCAIn(list []string, v string) bool {
	for _, x := range list { if TCALower(x) == v { return true } }
	return false
}

// TCAClassify 分类单个令牌。
func TCAClassify(tok string) string {
	v := TCALower(tok)
	switch {
	case TCAIn(TCABlock, v): return TCAClassBlock
	case TCAIn(TCAWarn, v): return TCAClassWarn
	case TCAIn(TCAAllow, v): return TCAClassAllow
	default: return TCAClassUnknown
	}
}
