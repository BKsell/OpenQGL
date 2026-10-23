package main

// basicauthurldirectoryguard.go —— URL 内嵌 Basic 认证目录。
//
// 威胁模型：
//   http://user:pass@ 或 ftp:// 携带凭据会被日志/历史记录留存，
//   且明文信道可被截获，应改用 TLS 上的头认证。纯字符查表，不用正则。

const (
	BAUClassBlock   = "block"
	BAUClassWarn    = "warn"
	BAUClassAllow   = "allow"
	BAUClassUnknown = "unknown"
)

var BAUBlock = []string{
	"://user:pass@",
	":@",
	"ftp://",
}

var BAUWarn = []string{
	"basic",
}

var BAUAllow = []string{
	"bearer-over-tls",
}

func BAULower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func BAUIn(list []string, v string) bool {
	for _, x := range list { if BAULower(x) == v { return true } }
	return false
}

// BAUClassify 分类单个令牌。
func BAUClassify(tok string) string {
	v := BAULower(tok)
	switch {
	case BAUIn(BAUBlock, v): return BAUClassBlock
	case BAUIn(BAUWarn, v): return BAUClassWarn
	case BAUIn(BAUAllow, v): return BAUClassAllow
	default: return BAUClassUnknown
	}
}
