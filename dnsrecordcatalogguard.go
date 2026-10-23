package main

// dnsrecordcatalogguard.go —— DNS 记录类型风险目录。
//
// 威胁模型：
//   DoH/自建解析会查询不同记录类型。AXFR 区域传送、ANY 放大、NULL/OPT/WKS 等可被滥用于侦察或放大攻击。
//   本模块按记录类型名分级，纯字符，不用正则。

const (
	DRCClassBlock   = "block"
	DRCClassWarn    = "warn"
	DRCClassAllow   = "allow"
	DRCClassUnknown = "unknown"
)

var DRCBlock = []string{
	"AXFR",
	"IXFR",
	"OPT",
	"NULL",
	"WKS",
	"HINFO",
	"RP",
}

var DRCWarn = []string{
	"ANY",
	"TXT",
	"MX",
	"NS",
	"SOA",
	"SRV",
	"CAA",
	"DNSKEY",
	"DS",
	"NSEC",
	"RRSIG",
	"TLSA",
	"SSHFP",
	"PTR",
}

var DRCAllow = []string{
	"A",
	"AAAA",
	"CNAME",
	"HTTPS",
	"SVCB",
}

func DRCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func DRCIn(list []string, v string) bool {
	for _, x := range list { if DRCLower(x) == v { return true } }
	return false
}

// DRCClassify 分类单个令牌。
func DRCClassify(tok string) string {
	v := DRCLower(tok)
	switch {
	case DRCIn(DRCBlock, v): return DRCClassBlock
	case DRCIn(DRCWarn, v): return DRCClassWarn
	case DRCIn(DRCAllow, v): return DRCClassAllow
	default: return DRCClassUnknown
	}
}
