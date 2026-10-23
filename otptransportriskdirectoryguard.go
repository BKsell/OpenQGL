package main

// otptransportriskdirectoryguard.go —— 一次性验证码传输风险目录。
//
// 威胁模型：
//   验证码出现在 URL/查询串、SMS 明文或备份码无保护会被截获/记录，
//   应走 App TOTP/通行密钥并哈希存储。纯字符查表，不用正则。

const (
	OTPClassBlock   = "block"
	OTPClassWarn    = "warn"
	OTPClassAllow   = "allow"
	OTPClassUnknown = "unknown"
)

var OTPBlock = []string{
	"otp-in-url",
	"code-query",
	"sms-plaintext",
	"backup-codes-plain",
}

var OTPWarn = []string{
	"sms-otp",
}

var OTPAllow = []string{
	"totp-app",
	"passkey",
	"hashed-backup",
}

func OTPLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func OTPIn(list []string, v string) bool {
	for _, x := range list { if OTPLower(x) == v { return true } }
	return false
}

// OTPClassify 分类单个令牌。
func OTPClassify(tok string) string {
	v := OTPLower(tok)
	switch {
	case OTPIn(OTPBlock, v): return OTPClassBlock
	case OTPIn(OTPWarn, v): return OTPClassWarn
	case OTPIn(OTPAllow, v): return OTPClassAllow
	default: return OTPClassUnknown
	}
}
