package main

// npmlifecyclescriptdirectoryguard.go —— npm 生命周期脚本目录。
//
// 威胁模型：
//   preinstall/postinstall/prepare 会在 npm install 时自动执行任意代码，
//   供应链投毒高发，应 --ignore-scripts 并审计。纯字符查表，不用正则。

const (
	NSLClassBlock   = "block"
	NSLClassWarn    = "warn"
	NSLClassAllow   = "allow"
	NSLClassUnknown = "unknown"
)

var NSLBlock = []string{
	"preinstall",
	"postinstall",
	"prepare",
	"preuninstall",
}

var NSLWarn = []string{
	"install",
}

var NSLAllow = []string{
	"explicit-script",
	"ignore-scripts",
}

func NSLLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func NSLIn(list []string, v string) bool {
	for _, x := range list { if NSLLower(x) == v { return true } }
	return false
}

// NSLClassify 分类单个令牌。
func NSLClassify(tok string) string {
	v := NSLLower(tok)
	switch {
	case NSLIn(NSLBlock, v): return NSLClassBlock
	case NSLIn(NSLWarn, v): return NSLClassWarn
	case NSLIn(NSLAllow, v): return NSLClassAllow
	default: return NSLClassUnknown
	}
}
