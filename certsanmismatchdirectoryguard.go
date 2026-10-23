package main

// certsanmismatchdirectoryguard.go —— 证书 SAN/CN 匹配目录。
//
// 威胁模型：
//   仅有 CN、无 SAN 或 SAN 与访问主机/IP 不匹配的证书不应信任，
//   现代校验只认 SAN。纯字符查表，不用正则。

const (
	SNMClassBlock   = "block"
	SNMClassWarn    = "warn"
	SNMClassAllow   = "allow"
	SNMClassUnknown = "unknown"
)

var SNMBlock = []string{
	"cn-only",
	"san-missing",
	"ip-mismatch",
	"name-mismatch",
}

var SNMWarn = []string{
	"multi-san",
	"wildcard-san",
}

var SNMAllow = []string{
	"dns-san-match",
	"ip-san-match",
}

func SNMLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SNMIn(list []string, v string) bool {
	for _, x := range list { if SNMLower(x) == v { return true } }
	return false
}

// SNMClassify 分类单个令牌。
func SNMClassify(tok string) string {
	v := SNMLower(tok)
	switch {
	case SNMIn(SNMBlock, v): return SNMClassBlock
	case SNMIn(SNMWarn, v): return SNMClassWarn
	case SNMIn(SNMAllow, v): return SNMClassAllow
	default: return SNMClassUnknown
	}
}
