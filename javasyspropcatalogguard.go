package main

// javasyspropcatalogguard.go —— JVM -D 系统属性风险目录。
//
// 威胁模型：
//   -D 系统属性可改变信任库、JNDI/RMI 代码来源、临时目录、安全管理器与原生库装载路径。整合包 profile
//   注入这些属性可导致远程类加载或凭据窃取。本模块按 key 名分级（value 另行审计），纯字符判定，不用正则。

// JSP 风险类别。
const (
	JSPClassBlock = "block"
	JSPClassWarn  = "warn"
	JSPClassAllow = "allow"
)

const (
	JSPReasonBlock   = "jsp-input-hits-blocked-catalog"
	JSPReasonWarn    = "jsp-input-hits-review-catalog"
	JSPReasonPrefix  = "jsp-input-hits-dangerous-prefix"
	JSPReasonEmpty   = "jsp-input-is-empty"
)

var JSPBlock = []string{
	"java.rmi.server.codebase",
	"com.sun.jndi.rmi.object.trustURLCodebase",
	"com.sun.jndi.cosnaming.object.trustURLCodebase",
	"com.sun.jndi.ldap.object.trustURLCodebase",
	"com.sun.jndi.ldap.object.trustSerialData",
	"java.security.manager",
	"javax.net.ssl.trustStore",
	"javax.net.ssl.keyStore",
	"javax.net.ssl.trustStorePassword",
	"javax.net.ssl.keyStorePassword",
	"jdk.attach.allowAttachSelf",
	"com.sun.management.jmxremote",
	"com.sun.management.jmxremote.port",
	"com.sun.management.jmxremote.authenticate",
	"com.sun.management.jmxremote.ssl",
	"java.security.policy",
	"jdk.tls.disabledAlgorithms",
	"jdk.jar.disabledAlgorithms",
	"jdk.certpath.disabledAlgorithms",
	"jdk.http.auth.tunneling.disabledSchemes",
}

var JSPWarn = []string{
	"java.io.tmpdir",
	"user.home",
	"user.dir",
	"jna.tmpdir",
	"jna.boot.library.path",
	"java.library.path",
	"java.class.path",
	"org.lwjgl.librarypath",
	"java.net.preferIPv4Stack",
	"http.proxyHost",
	"https.proxyHost",
	"http.nonProxyHosts",
	"socksProxyHost",
	"sun.net.client.defaultConnectTimeout",
	"http.agent",
}

var JSPAllow = []string{
	"file.encoding",
	"stdout.encoding",
	"stderr.encoding",
	"user.language",
	"user.country",
	"user.region",
	"sun.jnu.encoding",
	"java.awt.headless",
	"prism.order",
	"minecraft.api.auth.host",
	"minecraft.api.account.host",
	"minecraft.api.session.host",
	"minecraft.api.services.host",
	"log4j2.isThreadContextMapInheritable",
}

var JSPPrefixLit = []string{
	"javax.net.ssl.",
	"com.sun.jndi.",
	"java.rmi.",
	"com.sun.management.jmxremote",
	"java.security.",
	"jdk.tls.",
}
var JSPPrefixReason = []string{
	"system-property-rewrites-tls-trust",
	"system-property-touches-jndi",
	"system-property-touches-rmi",
	"system-property-enables-jmx-remote",
	"system-property-overrides-security-policy",
	"system-property-touches-tls",
}

// JSPFinding 表示一条命中。
type JSPFinding struct {
	Reason string
	Detail string
}

// JSPResult 是审计结果。
type JSPResult struct {
	Safe bool
	Findings []JSPFinding
}

func JSPLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func JSPIn(list []string, v string) bool {
	for _, x := range list { if JSPLower(x) == v { return true } }
	return false
}

func JSPSplit(in string) []string {
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

func JSPKeyPart(tok string) string {
	t := tok
	if len(t) >= 2 && t[0] == '-' && (t[1] == 'D' || t[1] == 'd') { t = t[2:] }
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// JSPHas 判定结果是否含某原因。
func JSPHas(r JSPResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// JSPAudit 审计输入字符串。
func JSPAudit(in string) JSPResult {
	res := JSPResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, JSPFinding{Reason: JSPReasonEmpty}); return res }
	toks := JSPSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := JSPLower(tok)
		key := JSPKeyPart(cmp)
		switch {
		case JSPIn(JSPBlock, key):
			res.Findings = append(res.Findings, JSPFinding{Reason: JSPReasonBlock, Detail: key})
		case JSPIn(JSPWarn, key):
			res.Findings = append(res.Findings, JSPFinding{Reason: JSPReasonWarn, Detail: key})
		}
		for i, lit := range JSPPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, JSPFinding{Reason: JSPPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
