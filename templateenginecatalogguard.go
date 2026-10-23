package main

// templateenginecatalogguard.go —— 模板引擎标识与危险表达式目录。
//
// 威胁模型：
//   识别 Jinja2/Freemarker/Velocity/Thymeleaf/Handlebars/MVEL 等模板注入面及危险表达式头。纯字符查表，不用正则。

const (
	TEDClassBlock   = "block"
	TEDClassWarn    = "warn"
	TEDClassAllow   = "allow"
	TEDClassUnknown = "unknown"
)

var TEDBlock = []string{
	"{{",
	"}}",
	"{%",
	"%}",
	"${",
	"}",
	"<%=",
	"<%",
	"freemarker.exec",
	"freemarker.template.utility.Execute",
	"freemarker.template.utility.ObjectConstructor",
	"freemarker.template.utility.JythonRuntime",
	"#assign",
	"<#assign",
	"#eval",
	"<#assign...?eval",
	"?new",
	"?api",
	"?eval",
	"freemarker.template.utility",
	"org.apache.commons.io",
	"java.lang.Runtime",
	"java.lang.ProcessBuilder",
	"javax.script",
	"groovy.lang.GroovyShell",
	"ScriptEngine",
	"Nashorn",
	"#set",
	"#servlet",
	"$class",
	"$util",
	"$ins",
	"$map",
	"T(",
	"*{T(java.lang.Runtime)",
	"T(java",
	"Runtime.getRuntime",
	"ProcessBuilder(",
}

var TEDWarn = []string{
	"{{config",
	"{{settings",
	"{{request",
	"{{self",
	"{{g",
	"{{cic",
	"${T(java",
	"{{'a'.getClass()",
	"class.forName",
	".class.classLoader",
	"getClass()",
	"forName",
	"invoke",
	"newInstance",
	"getMethod",
	"__class__",
	"__import__",
	"__builtins__",
	"{{namespace",
	"{%import",
	"{%include",
	"{{include",
	"#macro",
	"#function",
	"{{7*7",
	"${7*7}",
	"%24%7B",
}

var TEDAllow = []string{
	"jinja2",
	"freemarker",
	"velocity",
	"thymeleaf",
	"handlebars",
	"mustache",
	"mvel",
	"ognl",
	"spel",
	"liquid",
	"twig",
	"smarty",
	"pug",
	"ejs",
	"nunjucks",
	"autoescape",
	"sandbox",
	"whitelist",
}

func TEDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func TEDIn(list []string, v string) bool {
	for _, x := range list { if TEDLower(x) == v { return true } }
	return false
}

// TEDClassify 分类单个令牌。
func TEDClassify(tok string) string {
	v := TEDLower(tok)
	switch {
	case TEDIn(TEDBlock, v): return TEDClassBlock
	case TEDIn(TEDWarn, v): return TEDClassWarn
	case TEDIn(TEDAllow, v): return TEDClassAllow
	default: return TEDClassUnknown
	}
}
