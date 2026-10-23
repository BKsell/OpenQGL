package main

// javapermissioncatalogguard.go —— 危险 Java SecurityManager 权限目录。
//
// 威胁模型：
//   policy 或 check 中出现 AllPermission、exitVM、loadLibrary、任意文件读写、抑制反射检查即等于无沙箱。
//   本模块维护权限目标目录，纯字符判定，不用正则。

// JPC 风险类别。
const (
	JPCClassBlock = "block"
	JPCClassWarn  = "warn"
	JPCClassAllow = "allow"
)

const (
	JPCReasonBlock   = "jpc-input-hits-blocked-catalog"
	JPCReasonWarn    = "jpc-input-hits-review-catalog"
	JPCReasonPrefix  = "jpc-input-hits-dangerous-prefix"
	JPCReasonEmpty   = "jpc-input-is-empty"
)

var JPCBlock = []string{
	"java.security.AllPermission",
	"java.lang.RuntimePermission exitVM",
	"java.lang.RuntimePermission loadLibrary",
	"java.lang.RuntimePermission createClassLoader",
	"java.lang.reflect.ReflectPermission suppressAccessChecks",
	"java.io.FilePermission <<ALL FILES>>",
	"java.net.SocketPermission * connect,accept,listen",
	"java.security.SecurityPermission setPolicy",
	"javax.security.auth.AuthPermission doAs",
	"java.awt.AWTPermission createRobot",
	"java.lang.management.ManagementPermission control",
	"javax.management.MBeanPermission * *",
}

var JPCWarn = []string{
	"java.lang.RuntimePermission accessDeclaredMembers",
	"java.lang.RuntimePermission accessSystemClipboard",
	"java.io.FilePermission /-",
	"java.net.SocketPermission localhost:1024- listen",
	"java.awt.AWTPermission accessClipboard",
	"javax.net.ssl.SSLPermission setHostnameVerifier",
	"java.util.PropertyPermission * read,write",
}

var JPCAllow = []string{
	"java.util.PropertyPermission java.version read",
	"java.util.PropertyPermission os.name read",
	"java.lang.RuntimePermission accessClassInPackage.java.lang",
}

var JPCPrefixLit = []string{
	"AllPermission",
	"FilePermission <<ALL",
	"exitVM",
	"suppressAccessChecks",
}
var JPCPrefixReason = []string{
	"permission-grants-all",
	"permission-grants-all-files",
	"permission-allows-jvm-exit",
	"permission-suppresses-reflection-checks",
}

// JPCFinding 表示一条命中。
type JPCFinding struct {
	Reason string
	Detail string
}

// JPCResult 是审计结果。
type JPCResult struct {
	Safe bool
	Findings []JPCFinding
}

func JPCLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func JPCIn(list []string, v string) bool {
	for _, x := range list { if JPCLower(x) == v { return true } }
	return false
}

func JPCSplit(in string) []string {
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

func JPCKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// JPCHas 判定结果是否含某原因。
func JPCHas(r JPCResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// JPCAudit 审计输入字符串。
func JPCAudit(in string) JPCResult {
	res := JPCResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, JPCFinding{Reason: JPCReasonEmpty}); return res }
	toks := JPCSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := JPCLower(tok)
		key := cmp
		switch {
		case JPCIn(JPCBlock, key):
			res.Findings = append(res.Findings, JPCFinding{Reason: JPCReasonBlock, Detail: key})
		case JPCIn(JPCWarn, key):
			res.Findings = append(res.Findings, JPCFinding{Reason: JPCReasonWarn, Detail: key})
		}
		for i, lit := range JPCPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, JPCFinding{Reason: JPCPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
