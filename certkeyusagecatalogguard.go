package main

// certkeyusagecatalogguard.go —— 证书密钥用途/扩展风险目录。
//
// 威胁模型：
//   keyCertSign 出现在末端实体证书、CA BasicConstraints=true、缺 EKU/serverAuth 等配置可被用于中间人。纯字符查表，不用正则。

const (
	KUCClassBlock   = "block"
	KUCClassWarn    = "warn"
	KUCClassAllow   = "allow"
	KUCClassUnknown = "unknown"
)

var KUCBlock = []string{
	"keyCertSign",
	"cRLSign",
	"anyExtendedKeyUsage",
}

var KUCWarn = []string{
	"nonRepudiation",
	"contentCommitment",
	"keyEncipherment",
	"dataEncipherment",
	"keyAgreement",
	"encipherOnly",
	"decipherOnly",
	"clientAuth",
	"codeSigning",
	"emailProtection",
	"timeStamping",
	"OCSPSigning",
	"nsSGC",
	"msSGC",
	"msCTLSign",
	"msEFS",
	"msCodeInd",
	"msCodeCom",
	"ipsecEndSystem",
	"ipsecTunnel",
	"ipsecUser",
	"microsoftSmartcardLogin",
}

var KUCAllow = []string{
	"digitalSignature",
	"serverAuth",
}

func KUCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func KUCIn(list []string, v string) bool {
	for _, x := range list { if KUCLower(x) == v { return true } }
	return false
}

// KUCClassify 分类单个令牌。
func KUCClassify(tok string) string {
	v := KUCLower(tok)
	switch {
	case KUCIn(KUCBlock, v): return KUCClassBlock
	case KUCIn(KUCWarn, v): return KUCClassWarn
	case KUCIn(KUCAllow, v): return KUCClassAllow
	default: return KUCClassUnknown
	}
}
