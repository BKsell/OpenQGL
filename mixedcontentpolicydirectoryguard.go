package main

// mixedcontentpolicydirectoryguard.go —— 混合内容资源取值目录。
//
// 威胁模型：
//   https 页面加载 http:// 脚本/样式或 ws:// 会被中间人改写，
//   应 upgrade-insecure-requests 并全部走加密。纯字符查表，不用正则。

const (
	MXCClassBlock   = "block"
	MXCClassWarn    = "warn"
	MXCClassAllow   = "allow"
	MXCClassUnknown = "unknown"
)

var MXCBlock = []string{
	"http://",
	"ws://",
}

var MXCWarn = []string{
	"http://image",
	"http://media",
}

var MXCAllow = []string{
	"https://",
	"wss://",
}

func MXCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func MXCIn(list []string, v string) bool {
	for _, x := range list { if MXCLower(x) == v { return true } }
	return false
}

// MXCClassify 分类单个令牌。
func MXCClassify(tok string) string {
	v := MXCLower(tok)
	switch {
	case MXCIn(MXCBlock, v): return MXCClassBlock
	case MXCIn(MXCWarn, v): return MXCClassWarn
	case MXCIn(MXCAllow, v): return MXCClassAllow
	default: return MXCClassUnknown
	}
}
