package main

// emailauthresultcatalogguard.go —— 邮件 SPF/DKIM/DMARC 结果目录。
//
// 威胁模型：
//   Authentication-Results 中 fail/none/softfail 表示伪造或无保护应拒收/隔离，pass/reject 放行。纯字符查表，不用正则。

const (
	EMAClassBlock   = "block"
	EMAClassWarn    = "warn"
	EMAClassAllow   = "allow"
	EMAClassUnknown = "unknown"
)

var EMABlock = []string{
	"spf=fail",
	"dkim=none",
	"dmarc=fail",
	"dmarc=none",
	"spf=softfail",
}

var EMAWarn = []string{
	"spf=neutral",
	"spf=none",
	"dmarc=quarantine",
	"arc=none",
	"dmarc=missing",
	"spf=missing",
	"dkim=missing",
}

var EMAAllow = []string{
	"spf=pass",
	"dkim=pass",
	"dmarc=pass",
	"dmarc=reject",
	"arc=pass",
}

func EMALower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func EMAIn(list []string, v string) bool {
	for _, x := range list { if EMALower(x) == v { return true } }
	return false
}

// EMAClassify 分类单个令牌。
func EMAClassify(tok string) string {
	v := EMALower(tok)
	switch {
	case EMAIn(EMABlock, v): return EMAClassBlock
	case EMAIn(EMAWarn, v): return EMAClassWarn
	case EMAIn(EMAAllow, v): return EMAClassAllow
	default: return EMAClassUnknown
	}
}
