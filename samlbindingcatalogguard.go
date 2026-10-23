package main

// samlbindingcatalogguard.go —— SAML 绑定与确认类型目录。
//
// 威胁模型：
//   SAML HTTP-Redirect/POST/Artifact 绑定与 bearer/HoK 确认、NameID 格式的安全强度不同，松绑定需复核。纯字符查表，不用正则。

const (
	SBDClassBlock   = "block"
	SBDClassWarn    = "warn"
	SBDClassAllow   = "allow"
	SBDClassUnknown = "unknown"
)

var SBDBlock = []string{
	"sender-vouches",
	"HTTP-Artifact",
	"unspecified",
}

var SBDWarn = []string{
	"bearer",
	"HTTP-Redirect",
	"kerberos",
	"WindowsDomainQualifiedName",
	"X509SubjectName",
	"emailAddress",
	"SOAP",
	"PAOS",
	"URI",
}

var SBDAllow = []string{
	"holder-of-key",
	"HTTP-POST",
	"persistent",
	"transient",
	"entity",
}

func SBDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SBDIn(list []string, v string) bool {
	for _, x := range list { if SBDLower(x) == v { return true } }
	return false
}

// SBDClassify 分类单个令牌。
func SBDClassify(tok string) string {
	v := SBDLower(tok)
	switch {
	case SBDIn(SBDBlock, v): return SBDClassBlock
	case SBDIn(SBDWarn, v): return SBDClassWarn
	case SBDIn(SBDAllow, v): return SBDClassAllow
	default: return SBDClassUnknown
	}
}
