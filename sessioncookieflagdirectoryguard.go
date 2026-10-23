package main

// sessioncookieflagdirectoryguard.go —— 会话 Cookie 安全属性目录。
//
// 威胁模型：
//   会话 Cookie 缺 Secure/HttpOnly、SameSite=None 可被窃取或跨站携带，
//   应三属性齐全并独立 __Host- 前缀。纯字符查表，不用正则。

const (
	SCFClassBlock   = "block"
	SCFClassWarn    = "warn"
	SCFClassAllow   = "allow"
	SCFClassUnknown = "unknown"
)

var SCFBlock = []string{
	"no-httponly",
	"no-secure",
	"samesite=none",
}

var SCFWarn = []string{
	"session-expires",
}

var SCFAllow = []string{
	"secure",
	"httponly",
	"samesite=lax",
}

func SCFLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SCFIn(list []string, v string) bool {
	for _, x := range list { if SCFLower(x) == v { return true } }
	return false
}

// SCFClassify 分类单个令牌。
func SCFClassify(tok string) string {
	v := SCFLower(tok)
	switch {
	case SCFIn(SCFBlock, v): return SCFClassBlock
	case SCFIn(SCFWarn, v): return SCFClassWarn
	case SCFIn(SCFAllow, v): return SCFClassAllow
	default: return SCFClassUnknown
	}
}
