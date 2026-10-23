package main

// graphqlexposuredirectoryguard.go —— GraphQL 内省/深度风险目录。
//
// 威胁模型：
//   生产环境开放 __schema/__type 内省、无深度/别名限制会泄露 schema 并被嵌套查询打满，
//   应关内省并做成本限制。纯字符查表，不用正则。

const (
	GQDClassBlock   = "block"
	GQDClassWarn    = "warn"
	GQDClassAllow   = "allow"
	GQDClassUnknown = "unknown"
)

var GQDBlock = []string{
	"__schema",
	"__type",
	"introspection",
	"query-batching",
}

var GQDWarn = []string{
	"alias",
	"fragment",
}

var GQDAllow = []string{
	"named-operation",
	"depth-limit",
}

func GQDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func GQDIn(list []string, v string) bool {
	for _, x := range list { if GQDLower(x) == v { return true } }
	return false
}

// GQDClassify 分类单个令牌。
func GQDClassify(tok string) string {
	v := GQDLower(tok)
	switch {
	case GQDIn(GQDBlock, v): return GQDClassBlock
	case GQDIn(GQDWarn, v): return GQDClassWarn
	case GQDIn(GQDAllow, v): return GQDClassAllow
	default: return GQDClassUnknown
	}
}
