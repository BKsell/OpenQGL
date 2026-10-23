package main

// windowsalternatestreamdirectoryguard.go —— Windows 备用数据流名称目录。
//
// 威胁模型：
//   ::$DATA、:$INDEX 等 ADS 流可隐藏可执行内容或绕过扩展名检查，
//   Windows 文件名校验必须剥离流名。纯字符查表，不用正则。

const (
	ADSClassBlock   = "block"
	ADSClassWarn    = "warn"
	ADSClassAllow   = "allow"
	ADSClassUnknown = "unknown"
)

var ADSBlock = []string{
	":$data",
	":$index",
	"::",
	"zone.identifier",
}

var ADSWarn = []string{
	":stream",
	"alternate-stream",
}

var ADSAllow = []string{
	"normal-name",
}

func ADSLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func ADSIn(list []string, v string) bool {
	for _, x := range list { if ADSLower(x) == v { return true } }
	return false
}

// ADSClassify 分类单个令牌。
func ADSClassify(tok string) string {
	v := ADSLower(tok)
	switch {
	case ADSIn(ADSBlock, v): return ADSClassBlock
	case ADSIn(ADSWarn, v): return ADSClassWarn
	case ADSIn(ADSAllow, v): return ADSClassAllow
	default: return ADSClassUnknown
	}
}
