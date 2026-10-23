package main

// javaclasscatalogguard.go —— 危险 Java 类/方法/包目录。
//
// 威胁模型：
//   mod/插件可经反射、脚本引擎、JNDI、本地进程、Unsafe、setAccessible 突破沙箱。审计引用清单/反序列化
//   类型时本模块给出危险 API 分级，使用 / 与 . 两种内部形式归一匹配，纯字符，不用正则。

// JCC 风险类别。
const (
	JCCClassBlock = "block"
	JCCClassWarn  = "warn"
	JCCClassAllow = "allow"
)

const (
	JCCReasonBlock   = "jcc-input-hits-blocked-catalog"
	JCCReasonWarn    = "jcc-input-hits-review-catalog"
	JCCReasonPrefix  = "jcc-input-hits-dangerous-prefix"
	JCCReasonEmpty   = "jcc-input-is-empty"
)

var JCCBlock = []string{
	"java/lang/Runtime",
	"java.lang.Runtime",
	"java/lang/ProcessBuilder",
	"java.lang.ProcessBuilder",
	"javax/script/ScriptEngine",
	"javax/script/ScriptEngineManager",
	"jdk/internal/misc/Unsafe",
	"sun/misc/Unsafe",
	"javax/naming/InitialContext",
	"com/sun/jndi/ldap/LdapCtx",
	"java/rmi/Naming",
	"java/rmi/registry/LocateRegistry",
	"java/net/URLClassLoader",
	"java/beans/XMLDecoder",
	"java/io/ObjectInputStream",
	"java/lang/instrument/Instrumentation",
	"org/apache/commons/collections/functors/InvokerTransformer",
	"java/lang/invoke/MethodHandles",
	"java/lang/reflect/Method",
	"java/lang/reflect/Field",
}

var JCCWarn = []string{
	"java/lang/System",
	"java/lang/Class",
	"java/io/File",
	"java/nio/file/Files",
	"java/net/Socket",
	"java/net/URL",
	"java/net/HttpURLConnection",
	"java/sql/DriverManager",
	"java/awt/Robot",
	"java/awt/Clipboard",
	"javax/net/ssl/HttpsURLConnection",
	"java/util/prefs/Preferences",
}

var JCCAllow = []string{
	"java/lang/String",
	"java/util/List",
	"java/util/Map",
	"java/util/Set",
	"java/util/UUID",
	"java/time/Instant",
	"java/util/Optional",
	"java/util/stream/Stream",
	"java/nio/file/Path",
}

var JCCPrefixLit = []string{
	"sun/",
	"jdk/internal/",
	"com/sun/",
}
var JCCPrefixReason = []string{
	"class-references-sun-internal-package",
	"class-references-jdk-internal-package",
	"class-references-com-sun-package",
}

// JCCFinding 表示一条命中。
type JCCFinding struct {
	Reason string
	Detail string
}

// JCCResult 是审计结果。
type JCCResult struct {
	Safe bool
	Findings []JCCFinding
}

func JCCLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func JCCIn(list []string, v string) bool {
	for _, x := range list { if JCCLower(x) == v { return true } }
	return false
}

func JCCSplit(in string) []string {
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

func JCCKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// JCCHas 判定结果是否含某原因。
func JCCHas(r JCCResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// JCCAudit 审计输入字符串。
func JCCAudit(in string) JCCResult {
	res := JCCResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, JCCFinding{Reason: JCCReasonEmpty}); return res }
	toks := JCCSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := JCCLower(tok)
		key := cmp
		switch {
		case JCCIn(JCCBlock, key):
			res.Findings = append(res.Findings, JCCFinding{Reason: JCCReasonBlock, Detail: key})
		case JCCIn(JCCWarn, key):
			res.Findings = append(res.Findings, JCCFinding{Reason: JCCReasonWarn, Detail: key})
		}
		for i, lit := range JCCPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, JCCFinding{Reason: JCCPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
