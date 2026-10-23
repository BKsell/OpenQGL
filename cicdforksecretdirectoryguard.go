package main

// cicdforksecretdirectoryguard.go —— CI 拉取请求泄密配置目录。
//
// 威胁模型：
//   pull_request_target 检出 fork 代码却带 secrets、workflow 写权限 GITHUB_TOKEN 可被利用，
//   应改用 pull_request 并不授密钥。纯字符查表，不用正则。

const (
	CICClassBlock   = "block"
	CICClassWarn    = "warn"
	CICClassAllow   = "allow"
	CICClassUnknown = "unknown"
)

var CICBlock = []string{
	"pull_request_target",
	"secrets-on-fork",
	"workflow-write",
	"inline-fork-script",
}

var CICWarn = []string{
	"if-env-gate",
}

var CICAllow = []string{
	"pull_request",
	"read-only-token",
}

func CICLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CICIn(list []string, v string) bool {
	for _, x := range list { if CICLower(x) == v { return true } }
	return false
}

// CICClassify 分类单个令牌。
func CICClassify(tok string) string {
	v := CICLower(tok)
	switch {
	case CICIn(CICBlock, v): return CICClassBlock
	case CICIn(CICWarn, v): return CICClassWarn
	case CICIn(CICAllow, v): return CICClassAllow
	default: return CICClassUnknown
	}
}
