package main

// ldapfiltercatalogguard.go —— LDAP 过滤器注入字符目录。
//
// 威胁模型：
//   拼接 LDAP filter 时 *)(|=&!~ 与空字节可改变逻辑、绕过认证或枚举目录项。本目录按分隔后的令牌精确匹配，
//   纯字符，不发查询，不用正则。

// LDF 风险类别。
const (
	LDFClassBlock = "block"
	LDFClassWarn  = "warn"
	LDFClassAllow = "allow"
)

const (
	LDFReasonBlock   = "ldf-input-hits-blocked-catalog"
	LDFReasonWarn    = "ldf-input-hits-review-catalog"
	LDFReasonPrefix  = "ldf-input-hits-dangerous-prefix"
	LDFReasonEmpty   = "ldf-input-is-empty"
)

var LDFBlock = []string{
	"(",
	")",
	"*",
	"|",
	"=",
	"&",
	"!",
	"~",
	">",
	"<",
	"\\",
	"/",
	"NUL",
	"%00",
	"\\x00",
	"(uid=*",
	"(cn=*",
	"(|",
	"(&(",
	"(!",
	"(uid=",
	"admin*",
	"*)(uid=*",
}

var LDFWarn = []string{
	"cn",
	"uid",
	"mail",
	"samaccountname",
	"userprincipalname",
	"memberof",
	"objectclass",
	"objectcategory",
	"dc",
	"ou",
	"distinguishedname",
	"givenname",
	"sn",
	"telephonenumber",
	"description",
	"userpassword",
	"unicodepwd",
	"member",
	"group",
	"subtree",
	"onelevel",
	"base",
	"deref",
	"extensiblematch",
}

var LDFAllow = []string{
	"equals",
	"present",
	"substring",
	"escape",
	"attribute",
	"scope",
	"baseObject",
	"filter-safe",
	"cn-safe",
	"uid-safe",
}

var LDFPrefixLit = []string{
}
var LDFPrefixReason = []string{
}

// LDFFinding 表示一条命中。
type LDFFinding struct {
	Reason string
	Detail string
}

// LDFResult 是审计结果。
type LDFResult struct {
	Safe bool
	Findings []LDFFinding
}

func LDFLower(x string) string {
	return x
}

func LDFIn(list []string, v string) bool {
	for _, x := range list { if LDFLower(x) == v { return true } }
	return false
}

func LDFSplit(in string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(in); i++ {
		end := i == len(in)
		sep := false
		if !end { c := in[i]; sep = c == ' ' || c == '\t' || c == '\n' || c == '\r' }
		if end || sep {
			if start >= 0 { out = append(out, in[start:i]); start = -1 }
		} else if start < 0 {
			start = i
		}
	}
	return out
}

func LDFKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// LDFHas 判定结果是否含某原因。
func LDFHas(r LDFResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// LDFAudit 审计输入字符串。
func LDFAudit(in string) LDFResult {
	res := LDFResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, LDFFinding{Reason: LDFReasonEmpty}); return res }
	toks := LDFSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := LDFLower(tok)
		key := cmp
		switch {
		case LDFIn(LDFBlock, key):
			res.Findings = append(res.Findings, LDFFinding{Reason: LDFReasonBlock, Detail: key})
		case LDFIn(LDFWarn, key):
			res.Findings = append(res.Findings, LDFFinding{Reason: LDFReasonWarn, Detail: key})
		}
		for i, lit := range LDFPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, LDFFinding{Reason: LDFPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
