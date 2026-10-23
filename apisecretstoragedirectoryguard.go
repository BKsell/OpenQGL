package main

// apisecretstoragedirectoryguard.go —— API 密钥存放风险目录。
//
// 威胁模型：
//   client_secret/api_key 出现在 URL 查询串、硬编码或日志 JSON 中会被缓存/代理留存，
//   应放 Authorization 头或 HttpOnly Cookie。纯字符查表，不用正则。

const (
	ASSClassBlock   = "block"
	ASSClassWarn    = "warn"
	ASSClassAllow   = "allow"
	ASSClassUnknown = "unknown"
)

var ASSBlock = []string{
	"api_key=",
	"client_secret=",
	"password=",
	"?token=",
	"hardcoded-secret",
}

var ASSWarn = []string{
	"authorization-header-log",
}

var ASSAllow = []string{
	"http-only-cookie",
	"bearer-header",
}

func ASSLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func ASSIn(list []string, v string) bool {
	for _, x := range list { if ASSLower(x) == v { return true } }
	return false
}

// ASSClassify 分类单个令牌。
func ASSClassify(tok string) string {
	v := ASSLower(tok)
	switch {
	case ASSIn(ASSBlock, v): return ASSClassBlock
	case ASSIn(ASSWarn, v): return ASSClassWarn
	case ASSIn(ASSAllow, v): return ASSClassAllow
	default: return ASSClassUnknown
	}
}
