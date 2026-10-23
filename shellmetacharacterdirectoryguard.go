package main

// shellmetacharacterdirectoryguard.go —— Shell 元字符目录。
//
// 威胁模型：
//   反引号、$()、;、|、&、重定向与换行可改变命令语义构成注入，
//   拼系统命令应走参数数组而非字符串。纯字符查表，不用正则。

const (
	SHMClassBlock   = "block"
	SHMClassWarn    = "warn"
	SHMClassAllow   = "allow"
	SHMClassUnknown = "unknown"
)

var SHMBlock = []string{
	"`",
	"$()",
	"${",
	";",
	"|",
	"&",
	">",
	"<",
	"&&",
	"||",
	"\\n",
	"\\r",
}

var SHMWarn = []string{
	"%",
	"^",
	"~",
}

var SHMAllow = []string{
	"--",
	"=",
}

func SHMLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SHMIn(list []string, v string) bool {
	for _, x := range list { if SHMLower(x) == v { return true } }
	return false
}

// SHMClassify 分类单个令牌。
func SHMClassify(tok string) string {
	v := SHMLower(tok)
	switch {
	case SHMIn(SHMBlock, v): return SHMClassBlock
	case SHMIn(SHMWarn, v): return SHMClassWarn
	case SHMIn(SHMAllow, v): return SHMClassAllow
	default: return SHMClassUnknown
	}
}
