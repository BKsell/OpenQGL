package main

// yamlanchormergedirectoryguard.go —— YAML 锚点/多文档危险目录。
//
// 威胁模型：
//   !! 自定义标签、<< 合并键、多文档 --- 与外部锚点可触发意外实例化或注入额外文档，
//   应禁标签并按单文档解析。纯字符查表，不用正则。

const (
	YALClassBlock   = "block"
	YALClassWarn    = "warn"
	YALClassAllow   = "allow"
	YALClassUnknown = "unknown"
)

var YALBlock = []string{
	"!!",
	"<<",
	"---",
	"!<tag>",
}

var YALWarn = []string{
	"&anchor",
	"*alias",
}

var YALAllow = []string{
	"plain-map",
}

func YALLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func YALIn(list []string, v string) bool {
	for _, x := range list { if YALLower(x) == v { return true } }
	return false
}

// YALClassify 分类单个令牌。
func YALClassify(tok string) string {
	v := YALLower(tok)
	switch {
	case YALIn(YALBlock, v): return YALClassBlock
	case YALIn(YALWarn, v): return YALClassWarn
	case YALIn(YALAllow, v): return YALClassAllow
	default: return YALClassUnknown
	}
}
