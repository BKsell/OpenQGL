package main

// rangeabuseheaderdirectoryguard.go —— Range 头滥用取值目录。
//
// 威胁模型：
//   bytes=0- 全量、多区间大量片段可放大磁盘/内存开销形成 DoS，
//   应限制区间数与跨度。纯字符查表，不用正则。

const (
	RAHClassBlock   = "block"
	RAHClassWarn    = "warn"
	RAHClassAllow   = "allow"
	RAHClassUnknown = "unknown"
)

var RAHBlock = []string{
	"bytes=0-",
	"bytes=-",
	"bytes=0-,-1",
	"suffix=*",
}

var RAHWarn = []string{
	"if-range",
	"multi-range",
}

var RAHAllow = []string{
	"bytes=",
	"accept-ranges",
}

func RAHLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func RAHIn(list []string, v string) bool {
	for _, x := range list { if RAHLower(x) == v { return true } }
	return false
}

// RAHClassify 分类单个令牌。
func RAHClassify(tok string) string {
	v := RAHLower(tok)
	switch {
	case RAHIn(RAHBlock, v): return RAHClassBlock
	case RAHIn(RAHWarn, v): return RAHClassWarn
	case RAHIn(RAHAllow, v): return RAHClassAllow
	default: return RAHClassUnknown
	}
}
