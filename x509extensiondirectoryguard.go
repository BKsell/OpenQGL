package main

// x509extensiondirectoryguard.go —— X.509 证书扩展风险目录。
//
// 威胁模型：
//   TLS 证书扩展决定约束强度：keyCertSign CA、SAN 缺失、nameConstraints、policy、CRL/OCSP、SCT 等。
//   本目录按扩展短名/长名/OID 关键词分级，纯字符查表，不用正则。

const (
	XEDClassBlock   = "block"
	XEDClassWarn    = "warn"
	XEDClassAllow   = "allow"
	XEDClassUnknown = "unknown"
)

var XEDBlock = []string{
	"2.5.29.1",
	"2.5.29.31",
	"2.5.29.32",
	"2.5.29.37",
	"2.5.29.15",
	"2.5.29.17",
	"2.5.29.30",
	"2.5.29.18",
	"2.5.29.9",
	"keyCertSign",
	"cRLSign",
	"nameConstraints",
	"certificatePolicies",
	"policyConstraints",
	"basicConstraints",
	"extKeyUsage",
	"subjectAltName",
	"issuerAltName",
}

var XEDWarn = []string{
	"2.5.29.14",
	"2.5.29.35",
	"2.5.29.19",
	"2.5.29.20",
	"2.5.29.46",
	"2.5.29.10",
	"2.5.29.21",
	"2.5.29.24",
	"2.5.29.47",
	"2.5.29.53",
	"2.5.29.54",
	"subjectKeyIdentifier",
	"authorityKeyIdentifier",
	"cRLDistributionPoints",
	"authorityInfoAccess",
	"freshestCRL",
	"inhibitAnyPolicy",
	"policyMappings",
	"privateKeyUsagePeriod",
	"ct_precert_scts",
	"1.3.6.1.4.1.11129.2.4.2",
	"1.3.6.1.5.5.7.1.1",
	"1.3.6.1.5.5.7.1.11",
	"anyExtendedKeyUsage",
	"serverAuth",
	"clientAuth",
	"codeSigning",
	"emailProtection",
	"timeStamping",
	"OCSPSigning",
}

var XEDAllow = []string{
	"2.5.29.32.0",
	"2.5.29.40",
	"2.5.29.72",
	"2.5.29.73",
	"2.5.29.4",
	"2.5.29.2",
	"2.5.29.3",
	"subjectDirectoryAttributes",
	"keyUsage",
	"certificatePolicies.anyPolicy",
	"1.3.6.1.5.5.7.3.1",
	"1.3.6.1.5.5.7.3.2",
	"1.3.6.1.5.5.7.3.3",
	"1.3.6.1.5.5.7.3.4",
	"1.3.6.1.5.5.7.3.8",
	"1.3.6.1.5.5.7.3.9",
	"digitalSignature",
	"nonRepudiation",
	"contentCommitment",
	"keyEncipherment",
	"dataEncipherment",
	"keyAgreement",
	"encipherOnly",
	"decipherOnly",
}

func XEDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func XEDIn(list []string, v string) bool {
	for _, x := range list { if XEDLower(x) == v { return true } }
	return false
}

// XEDClassify 分类单个令牌。
func XEDClassify(tok string) string {
	v := XEDLower(tok)
	switch {
	case XEDIn(XEDBlock, v): return XEDClassBlock
	case XEDIn(XEDWarn, v): return XEDClassWarn
	case XEDIn(XEDAllow, v): return XEDClassAllow
	default: return XEDClassUnknown
	}
}
