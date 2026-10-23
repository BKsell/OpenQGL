package main

// githubactionspinningdirectoryguard.go —— GitHub Actions 引用固定目录。
//
// 威胁模型：
//   第三方 Action 引用 @main/@v1 浮动标签可被上游改写投毒，
//   应钉到完整 40 位 commit SHA。纯字符查表，不用正则。

const (
	GHAClassBlock   = "block"
	GHAClassWarn    = "warn"
	GHAClassAllow   = "allow"
	GHAClassUnknown = "unknown"
)

var GHABlock = []string{
	"@main",
	"@master",
	"@v1",
	"@v2",
	"@latest",
}

var GHAWarn = []string{
	"@short-sha",
}

var GHAAllow = []string{
	"@full-sha",
}

func GHALower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func GHAIn(list []string, v string) bool {
	for _, x := range list { if GHALower(x) == v { return true } }
	return false
}

// GHAClassify 分类单个令牌。
func GHAClassify(tok string) string {
	v := GHALower(tok)
	switch {
	case GHAIn(GHABlock, v): return GHAClassBlock
	case GHAIn(GHAWarn, v): return GHAClassWarn
	case GHAIn(GHAAllow, v): return GHAClassAllow
	default: return GHAClassUnknown
	}
}
