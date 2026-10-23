package main

// xxekeywordcatalogguard.go —— XXE 外部实体关键词目录。
//
// 威胁模型：
//   XML 解析前识别 DOCTYPE/ENTITY/SYSTEM/PUBLIC/CDATA 与 XInclude/XSL 外部引用关键字，配合禁外部实体。
//   纯字符精确匹配，不用正则。

// XKW 风险类别。
const (
	XKWClassBlock = "block"
	XKWClassWarn  = "warn"
	XKWClassAllow = "allow"
)

const (
	XKWReasonBlock   = "xkw-input-hits-blocked-catalog"
	XKWReasonWarn    = "xkw-input-hits-review-catalog"
	XKWReasonPrefix  = "xkw-input-hits-dangerous-prefix"
	XKWReasonEmpty   = "xkw-input-is-empty"
)

var XKWBlock = []string{
	"DOCTYPE",
	"ENTITY",
	"SYSTEM",
	"PUBLIC",
	"CDATA",
	"DOCTYPEENTITY",
	"ENTITYSYSTEM",
	"external",
	"external-general-entity",
	"external-parameter-entity",
	"load-external-dtd",
	"external-general",
	"external-parameter",
	"XInclude",
	"xi:include",
	"href",
	"parse",
	"xpointer",
	"xslt",
	"stylesheet",
	"transform",
	"document()",
	"unparsed-text",
	"xsl:include",
	"xsl:import",
	"schemaLocation",
	"noNamespaceSchemaLocation",
	"resolveExternals",
	"entityExpansion",
	"parameter-entities",
	"externalSubset",
	"feature-external-general",
	"feature-external-parameter",
	"feature-load-external",
	"feature-disallow-doctype",
	"accessExternalDTD",
	"accessExternalSchema",
	"FEATURE_SECURE_PROCESSING",
}

var XKWWarn = []string{
	"ENTITY_DECLARATION",
	"GENERAL_ENTITIES",
	"PARAMETER_ENTITIES",
	"IS_STANDALONE",
	"xml",
	"version",
	"encoding",
	"standalone",
	"namespace",
	"prefix",
	"localname",
	"element",
	"attribute",
	"comment",
	"processing-instruction",
	"textnode",
	"node",
	"namespaces",
	"resolveEntity",
	"InputSource",
	"EntityResolver",
	"SAXParserFactory",
	"DocumentBuilderFactory",
	"XMLReader",
	"setFeature",
	"disallow-doctype-decl",
}

var XKWAllow = []string{
	"json",
	"yaml",
	"toml",
	"csv",
	"plain",
	"utf-8",
	"ascii",
	"schema",
	"valid",
	"wellformed",
	"safemode",
	"secure",
	"whitelist",
	"allowlist",
}

var XKWPrefixLit = []string{
}
var XKWPrefixReason = []string{
}

// XKWFinding 表示一条命中。
type XKWFinding struct {
	Reason string
	Detail string
}

// XKWResult 是审计结果。
type XKWResult struct {
	Safe bool
	Findings []XKWFinding
}

func XKWLower(x string) string {
	return x
}

func XKWIn(list []string, v string) bool {
	for _, x := range list { if XKWLower(x) == v { return true } }
	return false
}

func XKWSplit(in string) []string {
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

func XKWKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// XKWHas 判定结果是否含某原因。
func XKWHas(r XKWResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// XKWAudit 审计输入字符串。
func XKWAudit(in string) XKWResult {
	res := XKWResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, XKWFinding{Reason: XKWReasonEmpty}); return res }
	toks := XKWSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := XKWLower(tok)
		key := cmp
		switch {
		case XKWIn(XKWBlock, key):
			res.Findings = append(res.Findings, XKWFinding{Reason: XKWReasonBlock, Detail: key})
		case XKWIn(XKWWarn, key):
			res.Findings = append(res.Findings, XKWFinding{Reason: XKWReasonWarn, Detail: key})
		}
		for i, lit := range XKWPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, XKWFinding{Reason: XKWPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
