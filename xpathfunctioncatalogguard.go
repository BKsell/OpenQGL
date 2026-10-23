package main

// xpathfunctioncatalogguard.go —— XPath 注入函数与轴目录。
//
// 威胁模型：
//   拼接 XPath 时 string-length/substring/contains/document/count 等函数与 or/and、通配可改写判定。纯字符查表，不用正则。

// XPF 风险类别。
const (
	XPFClassBlock = "block"
	XPFClassWarn  = "warn"
	XPFClassAllow = "allow"
)

const (
	XPFReasonBlock   = "xpf-input-hits-blocked-catalog"
	XPFReasonWarn    = "xpf-input-hits-review-catalog"
	XPFReasonPrefix  = "xpf-input-hits-dangerous-prefix"
	XPFReasonEmpty   = "xpf-input-is-empty"
)

var XPFBlock = []string{
	"or",
	"and",
	"not",
	"union",
	"|",
	"//",
	"/*",
	"*/",
	"*",
	"@*",
	"local-name",
	"name",
	"string-length",
	"substring",
	"substring-before",
	"substring-after",
	"contains",
	"starts-with",
	"translate",
	"normalize-space",
	"document",
	"doc",
	"collection",
	"unparsed-text",
	"count",
	"sum",
	"position",
	"last",
	"true",
	"false",
	"comment()",
	"processing-instruction()",
	"text()",
	"node()",
	"ancestor::",
	"descendant::",
	"following::",
	"preceding::",
	"parent::*",
	"child::*",
}

var XPFWarn = []string{
	"attribute::",
	"namespace::",
	"self",
	"following-sibling",
	"preceding-sibling",
	"lang",
	"number",
	"boolean",
	"ceiling",
	"floor",
	"round",
	"concat",
	"format-number",
	"namespace-uri",
	"generate-id",
	"key",
	"system-property",
	"element-available",
	"function-available",
	"distinct-values",
	"evaluate",
	"matches",
	"replace",
	"tokenize",
	"current",
}

var XPFAllow = []string{
	"eq",
	"ne",
	"lt",
	"le",
	"gt",
	"ge",
	"div",
	"idiv",
	"mod",
	"for",
	"let",
	"where",
	"order",
	"return",
	"if",
	"then",
	"else",
	"some",
	"every",
	"in",
	"as",
	"castable",
	"cast",
	"treat",
	"instance",
	"of",
}

var XPFPrefixLit = []string{
}
var XPFPrefixReason = []string{
}

// XPFFinding 表示一条命中。
type XPFFinding struct {
	Reason string
	Detail string
}

// XPFResult 是审计结果。
type XPFResult struct {
	Safe bool
	Findings []XPFFinding
}

func XPFLower(x string) string {
	return x
}

func XPFIn(list []string, v string) bool {
	for _, x := range list { if XPFLower(x) == v { return true } }
	return false
}

func XPFSplit(in string) []string {
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

func XPFKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// XPFHas 判定结果是否含某原因。
func XPFHas(r XPFResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// XPFAudit 审计输入字符串。
func XPFAudit(in string) XPFResult {
	res := XPFResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, XPFFinding{Reason: XPFReasonEmpty}); return res }
	toks := XPFSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := XPFLower(tok)
		key := cmp
		switch {
		case XPFIn(XPFBlock, key):
			res.Findings = append(res.Findings, XPFFinding{Reason: XPFReasonBlock, Detail: key})
		case XPFIn(XPFWarn, key):
			res.Findings = append(res.Findings, XPFFinding{Reason: XPFReasonWarn, Detail: key})
		}
		for i, lit := range XPFPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, XPFFinding{Reason: XPFPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
