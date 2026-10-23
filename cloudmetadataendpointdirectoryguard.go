package main

// cloudmetadataendpointdirectoryguard.go —— 云元数据地址目录。
//
// 威胁模型：
//   169.254.169.254、metadata.google.internal、100.100.100.200 等元数据端点可被 SSRF 窃取临时凭据，
//   应 IMDSv2/出向阻断。纯字符查表，不用正则。

const (
	CMIClassBlock   = "block"
	CMIClassWarn    = "warn"
	CMIClassAllow   = "allow"
	CMIClassUnknown = "unknown"
)

var CMIBlock = []string{
	"169.254.169.254",
	"metadata.google.internal",
	"100.100.100.200",
	"metadata.azure",
	"169.254.170.2",
}

var CMIWarn = []string{
	"imdsv1",
}

var CMIAllow = []string{
	"imdsv2",
	"blocked-egress",
}

func CMILower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CMIIn(list []string, v string) bool {
	for _, x := range list { if CMILower(x) == v { return true } }
	return false
}

// CMIClassify 分类单个令牌。
func CMIClassify(tok string) string {
	v := CMILower(tok)
	switch {
	case CMIIn(CMIBlock, v): return CMIClassBlock
	case CMIIn(CMIWarn, v): return CMIClassWarn
	case CMIIn(CMIAllow, v): return CMIClassAllow
	default: return CMIClassUnknown
	}
}
