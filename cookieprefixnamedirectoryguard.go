package main

// cookieprefixnamedirectoryguard.go —— 会话 Cookie 名与前缀目录。
//
// 威胁模型：
//   sessionid/jsessionid/phpsessid/sid 等知名会话 Cookie 名若不带 __Host-/__Secure- 前缀，
//   易被同名子域 Cookie 覆盖，敏感 Cookie 应加安全前缀。纯字符查表，不用正则。

const (
	CPNClassBlock   = "block"
	CPNClassWarn    = "warn"
	CPNClassAllow   = "allow"
	CPNClassUnknown = "unknown"
)

var CPNBlock = []string{
	"sessionid",
	"jsessionid",
	"phpsessid",
	"sid",
	"session",
	"token",
	"auth",
}

var CPNWarn = []string{
	"__secure-",
	"__host",
}

var CPNAllow = []string{
	"__host-",
	"__secure-csrf",
	"csrf-token",
}

func CPNLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CPNIn(list []string, v string) bool {
	for _, x := range list { if CPNLower(x) == v { return true } }
	return false
}

// CPNClassify 分类单个令牌。
func CPNClassify(tok string) string {
	v := CPNLower(tok)
	switch {
	case CPNIn(CPNBlock, v): return CPNClassBlock
	case CPNIn(CPNWarn, v): return CPNClassWarn
	case CPNIn(CPNAllow, v): return CPNClassAllow
	default: return CPNClassUnknown
	}
}
