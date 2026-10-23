package main

// tlsprotocolcatalogguard.go —— TLS/SSL 协议版本目录。
//
// 威胁模型：
//   SSLv2/SSLv3/TLS1.0/TLS1.1 已不安全需禁用，TLS1.2 复核配置，TLS1.3 放行。协议名与 wire version 都收录，
//   纯字符查表，不用正则。

const (
	TPVClassBlock   = "block"
	TPVClassWarn    = "warn"
	TPVClassAllow   = "allow"
	TPVClassUnknown = "unknown"
)

var TPVBlock = []string{
	"SSLv2",
	"SSLv3",
	"SSL2",
	"SSL3",
	"TLS1",
	"TLSv1",
	"TLS1.0",
	"TLSv1.0",
	"TLS_1_0",
	"0x0300",
	"0x0301",
	"0x0002",
	"SSL 2.0",
	"SSL 3.0",
	"TLS 1.0",
	"sslv2",
	"sslv3",
	"tls1.0",
}

var TPVWarn = []string{
	"TLS1.1",
	"TLSv1.1",
	"TLS_1_1",
	"0x0302",
	"TLS 1.1",
	"tls1.1",
	"TLS-FALLBACK-SCSV",
	"TLS_FALLBACK_SCSV",
}

var TPVAllow = []string{
	"TLS1.2",
	"TLSv1.2",
	"TLS_1_2",
	"0x0303",
	"TLS 1.2",
	"tls1.2",
	"TLS1.3",
	"TLSv1.3",
	"TLS_1_3",
	"0x0304",
	"TLS 1.3",
	"tls1.3",
}

func TPVLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func TPVIn(list []string, v string) bool {
	for _, x := range list { if TPVLower(x) == v { return true } }
	return false
}

// TPVClassify 分类单个令牌。
func TPVClassify(tok string) string {
	v := TPVLower(tok)
	switch {
	case TPVIn(TPVBlock, v): return TPVClassBlock
	case TPVIn(TPVWarn, v): return TPVClassWarn
	case TPVIn(TPVAllow, v): return TPVClassAllow
	default: return TPVClassUnknown
	}
}
