package main

// argumentinjectiondirectoryguard.go —— 参数注入符号目录。
//
// 威胁模型：
//   用户输入以 --/- 开头会被当成命令行选项，可触发 -e/-c/--exec 等危险参数，
//   传参前要用 -- 分隔或拒绝前导破折号。纯字符查表，不用正则。

const (
	AINClassBlock   = "block"
	AINClassWarn    = "warn"
	AINClassAllow   = "allow"
	AINClassUnknown = "unknown"
)

var AINBlock = []string{
	"--exec",
	"-c",
	"-e",
	"--enable",
	"--%",
	"-f",
	"-o",
}

var AINWarn = []string{
	"--",
	"-",
	"/flag",
}

var AINAllow = []string{
	"positional",
	"--",
}

func AINLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func AINIn(list []string, v string) bool {
	for _, x := range list { if AINLower(x) == v { return true } }
	return false
}

// AINClassify 分类单个令牌。
func AINClassify(tok string) string {
	v := AINLower(tok)
	switch {
	case AINIn(AINBlock, v): return AINClassBlock
	case AINIn(AINWarn, v): return AINClassWarn
	case AINIn(AINAllow, v): return AINClassAllow
	default: return AINClassUnknown
	}
}
