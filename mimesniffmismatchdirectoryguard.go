package main

// mimesniffmismatchdirectoryguard.go —— 上传 MIME 与内容风险目录。
//
// 威胁模型：
//   image/svg+xml 可携带脚本、text/html 与 application/octet-stream 混淆会被浏览器嗅探成可执行，
//   应结合内容校验并下发 nosniff。纯字符查表，不用正则。

const (
	MSMClassBlock   = "block"
	MSMClassWarn    = "warn"
	MSMClassAllow   = "allow"
	MSMClassUnknown = "unknown"
)

var MSMBlock = []string{
	"image/svg+xml",
	"text/html",
	"application/xhtml+xml",
	"text/xml",
}

var MSMWarn = []string{
	"application/octet-stream",
	"application/xml",
}

var MSMAllow = []string{
	"image/png",
	"image/jpeg",
	"text/css",
	"application/pdf",
}

func MSMLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func MSMIn(list []string, v string) bool {
	for _, x := range list { if MSMLower(x) == v { return true } }
	return false
}

// MSMClassify 分类单个令牌。
func MSMClassify(tok string) string {
	v := MSMLower(tok)
	switch {
	case MSMIn(MSMBlock, v): return MSMClassBlock
	case MSMIn(MSMWarn, v): return MSMClassWarn
	case MSMIn(MSMAllow, v): return MSMClassAllow
	default: return MSMClassUnknown
	}
}
