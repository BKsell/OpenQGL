package main

// serverbannerheaderdirectoryguard.go —— 服务指纹泄露头目录。
//
// 威胁模型：
//   Server/X-Powered-By/X-AspNet-Version 等回显技术栈与版本，便于攻击者匹配已知漏洞，
//   对外响应应隐藏。纯字符查表，不用正则。

const (
	SBHClassBlock   = "block"
	SBHClassWarn    = "warn"
	SBHClassAllow   = "allow"
	SBHClassUnknown = "unknown"
)

var SBHBlock = []string{
	"server",
	"x-powered-by",
	"x-aspnet-version",
	"x-aspnetmvc-version",
	"x-generator",
	"x-drupal-cache",
}

var SBHWarn = []string{
	"x-runtime",
	"x-amz-cf-id",
	"x-vercel-id",
	"via",
}

var SBHAllow = []string{
	"content-type",
	"content-length",
	"date",
}

func SBHLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SBHIn(list []string, v string) bool {
	for _, x := range list { if SBHLower(x) == v { return true } }
	return false
}

// SBHClassify 分类单个令牌。
func SBHClassify(tok string) string {
	v := SBHLower(tok)
	switch {
	case SBHIn(SBHBlock, v): return SBHClassBlock
	case SBHIn(SBHWarn, v): return SBHClassWarn
	case SBHIn(SBHAllow, v): return SBHClassAllow
	default: return SBHClassUnknown
	}
}
