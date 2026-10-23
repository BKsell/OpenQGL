package main

// expressioninjectioncatalogguard.go —— 表达式注入关键字目录。
//
// 威胁模型：
//   SpEL/OGNL/EL/MVEL/JEXL/模板表达式注入可 RCE，识别 T(、Runtime、exec、#cmd、${ 等关键字。
//   纯字符精确匹配，不求值，不用正则。

// EIN 风险类别。
const (
	EINClassBlock = "block"
	EINClassWarn  = "warn"
	EINClassAllow = "allow"
)

const (
	EINReasonBlock   = "ein-input-hits-blocked-catalog"
	EINReasonWarn    = "ein-input-hits-review-catalog"
	EINReasonPrefix  = "ein-input-hits-dangerous-prefix"
	EINReasonEmpty   = "ein-input-is-empty"
)

var EINBlock = []string{
	"T(",
	"T(java.lang.Runtime)",
	"Runtime",
	"getRuntime",
	"exec",
	"ProcessBuilder",
	"new",
	"class",
	"forName",
	"getMethod",
	"invoke",
	"getClass",
	"@java",
	"#cmd",
	"#rt",
	"#_memberAccess_",
	"#_memberAccess",
	"allowStaticMethodAccess",
	"excludedPackage",
	"excludedClass",
	"ognl",
	"Ognl",
	"ognl.OgnlRuntime",
	"@ognl.OgnlContext",
	"%{",
	"${",
	"#{",
	"#this",
	"memberAccess",
	"StrSubstitutor",
	"SpelExpressionParser",
	"ExpressionParser",
	"parseExpression",
	"getValue",
	"setValue",
	"ScriptEngine",
	"eval",
	"GroovyShell",
	"evaluate",
	"MVEL",
	"JEXL",
	"JexlEngine",
	"ELProcessor",
	"MethodExpression",
	"ValueExpression",
	"createValueExpression",
	"createMethodExpression",
	"#_",
	"#root",
	"#context",
	"#application",
	"#request",
	"#session",
	"#parameters",
	"#attr",
	"#_memberAccess.excludeProperties",
	"java.lang.ProcessBuilder",
	"java.lang.Runtime",
	"javax.script.ScriptEngineManager",
	"freemarker",
	"template.utility",
	"Execute",
	"<#assign",
	"<#import",
	"velocity",
	"#set",
	"#foreach",
	"#parse",
	"#include",
	"$class",
	"$runtime",
	"$process",
	"SSTI",
}

var EINWarn = []string{
	"spel",
	"expression",
	"expr",
	"el",
	"juel",
	"groovy",
	"nashorn",
	"js",
	"javascript",
	"rhino",
	"graalvm",
	"polyglot",
	"interpolate",
	"template",
	"placeholder",
	"resolver",
	"lookup",
	"context",
	"variable",
	"property",
	"method",
	"static",
	"reflect",
	"sandbox",
	"whitelist",
	"blacklist",
	"restrict",
	"permit",
	"deny",
	"bypass",
}

var EINAllow = []string{
	"literal",
	"constant",
	"number",
	"string",
	"boolean",
	"arithmetic",
	"comparison",
	"logical",
	"conditional",
	"safe",
	"secure",
	"parameter",
	"bound",
	"typed",
}

var EINPrefixLit = []string{
}
var EINPrefixReason = []string{
}

// EINFinding 表示一条命中。
type EINFinding struct {
	Reason string
	Detail string
}

// EINResult 是审计结果。
type EINResult struct {
	Safe bool
	Findings []EINFinding
}

func EINLower(x string) string {
	return x
}

func EINIn(list []string, v string) bool {
	for _, x := range list { if EINLower(x) == v { return true } }
	return false
}

func EINSplit(in string) []string {
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

func EINKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// EINHas 判定结果是否含某原因。
func EINHas(r EINResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// EINAudit 审计输入字符串。
func EINAudit(in string) EINResult {
	res := EINResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, EINFinding{Reason: EINReasonEmpty}); return res }
	toks := EINSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := EINLower(tok)
		key := cmp
		switch {
		case EINIn(EINBlock, key):
			res.Findings = append(res.Findings, EINFinding{Reason: EINReasonBlock, Detail: key})
		case EINIn(EINWarn, key):
			res.Findings = append(res.Findings, EINFinding{Reason: EINReasonWarn, Detail: key})
		}
		for i, lit := range EINPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, EINFinding{Reason: EINPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
