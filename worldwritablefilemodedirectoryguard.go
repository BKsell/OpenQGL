package main

// worldwritablefilemodedirectoryguard.go —— 危险文件权限位目录。
//
// 威胁模型：
//   0777/0666、setuid/setgid 位使任意用户可写或提权，
//   凭据/配置文件应收紧到 0600/0640。纯字符查表，不用正则。

const (
	FPBClassBlock   = "block"
	FPBClassWarn    = "warn"
	FPBClassAllow   = "allow"
	FPBClassUnknown = "unknown"
)

var FPBBlock = []string{
	"777",
	"666",
	"setuid",
	"setgid",
}

var FPBWarn = []string{
	"775",
	"664",
}

var FPBAllow = []string{
	"600",
	"640",
	"644",
}

func FPBLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func FPBIn(list []string, v string) bool {
	for _, x := range list { if FPBLower(x) == v { return true } }
	return false
}

// FPBClassify 分类单个令牌。
func FPBClassify(tok string) string {
	v := FPBLower(tok)
	switch {
	case FPBIn(FPBBlock, v): return FPBClassBlock
	case FPBIn(FPBWarn, v): return FPBClassWarn
	case FPBIn(FPBAllow, v): return FPBClassAllow
	default: return FPBClassUnknown
	}
}
