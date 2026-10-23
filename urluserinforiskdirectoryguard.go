package main

// urluserinforiskdirectoryguard.go —— URL userinfo 凭据目录。
//
// 威胁模型：
//   http://user:pass@host 形式把凭据放进 URL，会进入日志/历史/Referer，
//   应改用 Authorization 头。纯字符查表，不用正则。

const (
	UUIClassBlock   = "block"
	UUIClassWarn    = "warn"
	UUIClassAllow   = "allow"
	UUIClassUnknown = "unknown"
)

var UUIBlock = []string{
	"@",
	"basic-in-url",
	":%40",
	"userinfo",
}

var UUIWarn = []string{
	"authorization",
	"proxy-authorization",
}

var UUIAllow = []string{
	"https-no-cred",
	"bearer",
}

func UUILower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func UUIIn(list []string, v string) bool {
	for _, x := range list { if UUILower(x) == v { return true } }
	return false
}

// UUIClassify 分类单个令牌。
func UUIClassify(tok string) string {
	v := UUILower(tok)
	switch {
	case UUIIn(UUIBlock, v): return UUIClassBlock
	case UUIIn(UUIWarn, v): return UUIClassWarn
	case UUIIn(UUIAllow, v): return UUIClassAllow
	default: return UUIClassUnknown
	}
}
