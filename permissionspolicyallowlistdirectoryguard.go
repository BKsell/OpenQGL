package main

// permissionspolicyallowlistdirectoryguard.go —— 权限策略 allowlist 取值目录。
//
// 威胁模型：
//   camera/geolocation 等特性策略写成 * 或空 () 语义被放宽时会把能力授予任意来源，
//   应显式 self 或指定源。纯字符查表，不用正则。

const (
	PPAClassBlock   = "block"
	PPAClassWarn    = "warn"
	PPAClassAllow   = "allow"
	PPAClassUnknown = "unknown"
)

var PPABlock = []string{
	"*",
	"()",
}

var PPAWarn = []string{
	"self",
	"src",
}

var PPAAllow = []string{
	"none",
	"()",
	"\"self\"",
}

func PPALower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func PPAIn(list []string, v string) bool {
	for _, x := range list { if PPALower(x) == v { return true } }
	return false
}

// PPAClassify 分类单个令牌。
func PPAClassify(tok string) string {
	v := PPALower(tok)
	switch {
	case PPAIn(PPABlock, v): return PPAClassBlock
	case PPAIn(PPAWarn, v): return PPAClassWarn
	case PPAIn(PPAAllow, v): return PPAClassAllow
	default: return PPAClassUnknown
	}
}
