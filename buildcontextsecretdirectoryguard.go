package main

// buildcontextsecretdirectoryguard.go —— 构建上下文敏感文件目录。
//
// 威胁模型：
//   构建上下文带入 .env/*.pem/日志/源码历史会使镜像层含密钥，
//   应显式白名单 dockerignore。纯字符查表，不用正则。

const (
	DSIClassBlock   = "block"
	DSIClassWarn    = "warn"
	DSIClassAllow   = "allow"
	DSIClassUnknown = "unknown"
)

var DSIBlock = []string{
	".env",
	"*.pem",
	"*.key",
	"logs/",
	".git/",
}

var DSIWarn = []string{
	"*.log",
	"node_modules/",
}

var DSIAllow = []string{
	"dockerignore-listed",
}

func DSILower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func DSIIn(list []string, v string) bool {
	for _, x := range list { if DSILower(x) == v { return true } }
	return false
}

// DSIClassify 分类单个令牌。
func DSIClassify(tok string) string {
	v := DSILower(tok)
	switch {
	case DSIIn(DSIBlock, v): return DSIClassBlock
	case DSIIn(DSIWarn, v): return DSIClassWarn
	case DSIIn(DSIAllow, v): return DSIClassAllow
	default: return DSIClassUnknown
	}
}
