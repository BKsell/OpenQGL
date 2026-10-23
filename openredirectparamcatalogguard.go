package main

// openredirectparamcatalogguard.go —— 开放重定向参数名目录。
//
// 威胁模型：
//   url/redirect/next/to/return/continue 等参数常用于开放重定向钓鱼，取值必须白名单校验。纯字符查表，不用正则。

// ORP 风险类别。
const (
	ORPClassBlock = "block"
	ORPClassWarn  = "warn"
	ORPClassAllow = "allow"
)

const (
	ORPReasonBlock   = "orp-input-hits-blocked-catalog"
	ORPReasonWarn    = "orp-input-hits-review-catalog"
	ORPReasonPrefix  = "orp-input-hits-dangerous-prefix"
	ORPReasonEmpty   = "orp-input-is-empty"
)

var ORPBlock = []string{
	"url",
	"redirect",
	"redirect_uri",
	"redirect_url",
	"redirecturl",
	"return",
	"returnurl",
	"return_url",
	"returnTo",
	"return_to",
	"next",
	"nexturl",
	"next_url",
	"to",
	"goto",
	"target",
	"dest",
	"destination",
	"continue",
	"continueto",
	"forward",
	"rurl",
	"u",
	"uri",
	"link",
	"out",
	"view",
	"file",
	"path",
	"load",
	"redir",
	"go",
	"location",
	"callback",
	"done",
}

var ORPWarn = []string{
	"ref",
	"reference",
	"referrer",
	"back",
	"previous",
	"from",
	"src",
	"source",
	"fromurl",
	"redirectto",
	"jump",
	"jumpto",
	"nav",
	"navigate",
	"land",
	"landing",
	"after",
	"post",
	"postlogin",
	"post_logout",
	"success",
	"success_url",
	"failure",
	"failure_url",
	"cancel",
	"abort",
	"exiturl",
	"home",
	"homeurl",
}

var ORPAllow = []string{
	"id",
	"page",
	"limit",
	"offset",
	"sort",
	"order",
	"q",
	"query",
	"search",
	"lang",
	"theme",
	"version",
	"format",
}

var ORPPrefixLit = []string{
}
var ORPPrefixReason = []string{
}

// ORPFinding 表示一条命中。
type ORPFinding struct {
	Reason string
	Detail string
}

// ORPResult 是审计结果。
type ORPResult struct {
	Safe bool
	Findings []ORPFinding
}

func ORPLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func ORPIn(list []string, v string) bool {
	for _, x := range list { if ORPLower(x) == v { return true } }
	return false
}

func ORPSplit(in string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(in); i++ {
		if i == len(in) || in[i] == ',' { out = append(out, in[start:i]); start = i + 1 }
	}
	return out
}

func ORPKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// ORPHas 判定结果是否含某原因。
func ORPHas(r ORPResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// ORPAudit 审计输入字符串。
func ORPAudit(in string) ORPResult {
	res := ORPResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, ORPFinding{Reason: ORPReasonEmpty}); return res }
	toks := ORPSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := ORPLower(tok)
		key := cmp
		switch {
		case ORPIn(ORPBlock, key):
			res.Findings = append(res.Findings, ORPFinding{Reason: ORPReasonBlock, Detail: key})
		case ORPIn(ORPWarn, key):
			res.Findings = append(res.Findings, ORPFinding{Reason: ORPReasonWarn, Detail: key})
		}
		for i, lit := range ORPPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, ORPFinding{Reason: ORPPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
