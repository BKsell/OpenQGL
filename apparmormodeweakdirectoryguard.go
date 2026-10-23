package main

// apparmormodeweakdirectoryguard.go —— AppArmor 模式目录。
//
// 威胁模型：
//   profile 为 unconfined/complain 不强制访问控制，
//   容器与服务应以 enforce 运行。纯字符查表，不用正则。

const (
	AAPClassBlock   = "block"
	AAPClassWarn    = "warn"
	AAPClassAllow   = "allow"
	AAPClassUnknown = "unknown"
)

var AAPBlock = []string{
	"unconfined",
	"complain",
	"disabled",
}

var AAPWarn = []string{
	"partial-profile",
}

var AAPAllow = []string{
	"enforce",
}

func AAPLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func AAPIn(list []string, v string) bool {
	for _, x := range list { if AAPLower(x) == v { return true } }
	return false
}

// AAPClassify 分类单个令牌。
func AAPClassify(tok string) string {
	v := AAPLower(tok)
	switch {
	case AAPIn(AAPBlock, v): return AAPClassBlock
	case AAPIn(AAPWarn, v): return AAPClassWarn
	case AAPIn(AAPAllow, v): return AAPClassAllow
	default: return AAPClassUnknown
	}
}
