package main

// http2resetflooddirectoryguard.go —— HTTP/2 Rapid Reset 相关取值目录。
//
// 威胁模型：
//   短连接内高频 RST_STREAM/PRIORITY 取消是 Rapid Reset 放大手法，
//   并发流上限与异常取消速率要受限。纯字符查表，不用正则。

const (
	RSTClassBlock   = "block"
	RSTClassWarn    = "warn"
	RSTClassAllow   = "allow"
	RSTClassUnknown = "unknown"
)

var RSTBlock = []string{
	"rst_stream",
	"rapid-reset",
	"cancel-before-response",
}

var RSTWarn = []string{
	"priority",
	"max_concurrent_streams",
}

var RSTAllow = []string{
	"window_update",
	"settings",
}

func RSTLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func RSTIn(list []string, v string) bool {
	for _, x := range list { if RSTLower(x) == v { return true } }
	return false
}

// RSTClassify 分类单个令牌。
func RSTClassify(tok string) string {
	v := RSTLower(tok)
	switch {
	case RSTIn(RSTBlock, v): return RSTClassBlock
	case RSTIn(RSTWarn, v): return RSTClassWarn
	case RSTIn(RSTAllow, v): return RSTClassAllow
	default: return RSTClassUnknown
	}
}
