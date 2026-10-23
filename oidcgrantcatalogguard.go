package main

// oidcgrantcatalogguard.go —— OAuth/OIDC grant_type 风险目录。
//
// 威胁模型：
//   password 与 implicit(已废弃) 直传凭据、device_code 钓鱼、client_credentials 误用到用户场景需阻断/复核。纯字符查表，不用正则。

const (
	OGCClassBlock   = "block"
	OGCClassWarn    = "warn"
	OGCClassAllow   = "allow"
	OGCClassUnknown = "unknown"
)

var OGCBlock = []string{
	"password",
	"implicit",
}

var OGCWarn = []string{
	"client_credentials",
	"urn:ietf:params:oauth:grant-type:device_code",
	"urn:ietf:params:oauth:grant-type:jwt-bearer",
	"urn:ietf:params:oauth:grant-type:saml2-bearer",
	"urn:ietf:params:oauth:grant-type:token-exchange",
	"refresh_token",
	"hybrid",
}

var OGCAllow = []string{
	"authorization_code",
}

func OGCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func OGCIn(list []string, v string) bool {
	for _, x := range list { if OGCLower(x) == v { return true } }
	return false
}

// OGCClassify 分类单个令牌。
func OGCClassify(tok string) string {
	v := OGCLower(tok)
	switch {
	case OGCIn(OGCBlock, v): return OGCClassBlock
	case OGCIn(OGCWarn, v): return OGCClassWarn
	case OGCIn(OGCAllow, v): return OGCClassAllow
	default: return OGCClassUnknown
	}
}
