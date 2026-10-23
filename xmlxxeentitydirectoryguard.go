package main

// xmlxxeentitydirectoryguard.go —— XML XXE 关键字目录。
//
// 威胁模型：
//   DOCTYPE/ENTITY/SYSTEM/PUBLIC/XInclude 与外部实体开关导致 XXE 读文件/SSRF，
//   解析器应禁外部实体并不带 DTD。纯字符查表，不用正则。

const (
	XXDClassBlock   = "block"
	XXDClassWarn    = "warn"
	XXDClassAllow   = "allow"
	XXDClassUnknown = "unknown"
)

var XXDBlock = []string{
	"<!doctype",
	"<!entity",
	"system",
	"public",
	"xinclude",
	"external-general-entities",
	"external-parameter-entities",
}

var XXDWarn = []string{
	"parameter-entity",
	"load-dtd",
}

var XXDAllow = []string{
	"standalone",
	"no-dtd",
}

func XXDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func XXDIn(list []string, v string) bool {
	for _, x := range list { if XXDLower(x) == v { return true } }
	return false
}

// XXDClassify 分类单个令牌。
func XXDClassify(tok string) string {
	v := XXDLower(tok)
	switch {
	case XXDIn(XXDBlock, v): return XXDClassBlock
	case XXDIn(XXDWarn, v): return XXDClassWarn
	case XXDIn(XXDAllow, v): return XXDClassAllow
	default: return XXDClassUnknown
	}
}
