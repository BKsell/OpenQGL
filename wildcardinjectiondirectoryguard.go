package main

// wildcardinjectiondirectoryguard.go —— 路径通配注入字符目录。
//
// 威胁模型：
//   * ? [ ] { } 与 ** 会被 shell/glob 展开，配合文件名可注入额外目标，
//   应传字面值或自行安全展开。纯字符查表，不用正则。

const (
	WLIClassBlock   = "block"
	WLIClassWarn    = "warn"
	WLIClassAllow   = "allow"
	WLIClassUnknown = "unknown"
)

var WLIBlock = []string{
	"*",
	"?",
	"[",
	"]",
	"{",
	"}",
	"**",
}

var WLIWarn = []string{
	"~",
}

var WLIAllow = []string{
	"literal",
}

func WLILower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func WLIIn(list []string, v string) bool {
	for _, x := range list { if WLILower(x) == v { return true } }
	return false
}

// WLIClassify 分类单个令牌。
func WLIClassify(tok string) string {
	v := WLILower(tok)
	switch {
	case WLIIn(WLIBlock, v): return WLIClassBlock
	case WLIIn(WLIWarn, v): return WLIClassWarn
	case WLIIn(WLIAllow, v): return WLIClassAllow
	default: return WLIClassUnknown
	}
}
