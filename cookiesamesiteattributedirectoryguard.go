package main

// cookiesamesiteattributedirectoryguard.go —— Cookie SameSite 取值目录。
//
// 威胁模型：
//   SameSite=None 的会话 Cookie 可被跨站携带，未配 Secure 时扩大 CSRF 面，
//   状态变更 Cookie 应 Lax/Strict。纯字符查表，不用正则。

const (
	CSAClassBlock   = "block"
	CSAClassWarn    = "warn"
	CSAClassAllow   = "allow"
	CSAClassUnknown = "unknown"
)

var CSABlock = []string{
	"none",
	"",
}

var CSAWarn = []string{
	"lax",
	"unset",
}

var CSAAllow = []string{
	"strict",
	"samesite=lax",
	"samesite=strict",
}

func CSALower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CSAIn(list []string, v string) bool {
	for _, x := range list { if CSALower(x) == v { return true } }
	return false
}

// CSAClassify 分类单个令牌。
func CSAClassify(tok string) string {
	v := CSALower(tok)
	switch {
	case CSAIn(CSABlock, v): return CSAClassBlock
	case CSAIn(CSAWarn, v): return CSAClassWarn
	case CSAIn(CSAAllow, v): return CSAClassAllow
	default: return CSAClassUnknown
	}
}
