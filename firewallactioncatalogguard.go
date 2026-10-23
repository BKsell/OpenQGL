package main

// firewallactioncatalogguard.go —— 防火墙/网络策略动作目录。
//
// 威胁模型：
//   ALLOW/ACCEPT 对 0.0.0.0/0 高危端口、LOG/DROP/REJECT 语义与 bypass/override 规则需审计。纯字符查表，不用正则。

const (
	FWAClassBlock   = "block"
	FWAClassWarn    = "warn"
	FWAClassAllow   = "allow"
	FWAClassUnknown = "unknown"
)

var FWABlock = []string{
	"BYPASS",
	"OVERRIDE",
	"ANY",
	"0.0.0.0/0",
	"::/0",
	"ANY-ANY",
}

var FWAWarn = []string{
	"ALLOW",
	"ACCEPT",
	"PERMIT",
	"PASS",
	"MASQUERADE",
	"DNAT",
	"SNAT",
	"REDIRECT",
	"FORWARD",
	"PREROUTING",
	"POSTROUTING",
	"NEW",
	"INVALID",
}

var FWAAllow = []string{
	"DROP",
	"REJECT",
	"DENY",
	"BLOCK",
	"LOG",
	"RETURN",
	"ESTABLISHED",
	"RELATED",
	"INPUT",
	"OUTPUT",
}

func FWALower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func FWAIn(list []string, v string) bool {
	for _, x := range list { if FWALower(x) == v { return true } }
	return false
}

// FWAClassify 分类单个令牌。
func FWAClassify(tok string) string {
	v := FWALower(tok)
	switch {
	case FWAIn(FWABlock, v): return FWAClassBlock
	case FWAIn(FWAWarn, v): return FWAClassWarn
	case FWAIn(FWAAllow, v): return FWAClassAllow
	default: return FWAClassUnknown
	}
}
