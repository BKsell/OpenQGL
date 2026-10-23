package main

// javasyspropertydirectoryguard.go —— Java 系统属性全量风险目录。
//
// 威胁模型：
//   -D 系统属性改变信任库/JNDI/RMI/临时目录/原生库路径。本目录对常见 HotSpot/Java/库属性按阻断/复核/常规
//   分级，按 key 名判定，value 另审，纯字符，不用正则。

// JAD 风险类别。
const (
	JADClassBlock = "block"
	JADClassWarn  = "warn"
	JADClassAllow = "allow"
)

const (
	JADReasonBlock   = "jad-input-hits-blocked-catalog"
	JADReasonWarn    = "jad-input-hits-review-catalog"
	JADReasonPrefix  = "jad-input-hits-dangerous-prefix"
	JADReasonEmpty   = "jad-input-is-empty"
)

var JADBlock = []string{
	"java.rmi.server.hostname",
	"com.sun.management.jmxremote",
	"com.sun.management.jmxremote.port",
	"com.sun.management.jmxremote.rmi.port",
	"com.sun.management.jmxremote.authenticate",
	"com.sun.management.jmxremote.ssl",
	"com.sun.management.jmxremote.local.only",
	"com.sun.jndi.ldap.object.trustURLCodebase",
	"com.sun.jndi.rmi.object.trustURLCodebase",
	"com.sun.jndi.cosnaming.object.trustURLCodebase",
	"java.naming.factory.initial",
	"java.naming.provider.url",
	"java.naming.factory.url.pkgs",
	"java.naming.factory.control",
	"jdk.jndi.object.factoriesFilter",
	"java.security.manager",
	"java.security.policy",
	"java.security.properties",
	"java.security.egd",
	"java.security.disabledAlgorithms",
	"jdk.tls.disabledAlgorithms",
	"jdk.certpath.disabledAlgorithms",
	"jdk.jar.disabledAlgorithms",
	"jdk.security.legacyAlgorithms",
	"javax.net.ssl.trustStore",
	"javax.net.ssl.trustStorePassword",
	"javax.net.ssl.trustStoreType",
	"javax.net.ssl.keyStore",
	"javax.net.ssl.keyStorePassword",
	"javax.net.ssl.keyStoreType",
	"javax.net.ssl.key",
	"javax.net.ssl.trust",
	"javax.net.ssl.sessionCacheSize",
	"jdk.tls.client.protocols",
	"https.protocols",
	"jdk.tls.allowUnsafeServerCertChange",
	"sun.security.ssl.allowUnsafeRenegotiation",
	"sun.security.ssl.allowLegacyHelloMessages",
	"com.sun.net.ssl.checkRevocation",
	"sun.security.ssl.allowUnsafeRenegotiationClient",
	"jdk.tls.rejectClientInitiatedRenegotiation",
	"jdk.tls.namedGroups",
	"jdk.tls.ephemeralDHKeySize",
	"jdk.tls.server.defaultDHEParameters",
	"jdk.tls.allowLegacyMasterSecret",
	"jdk.tls.server.enableSessionTicketExtension",
	"jdk.tls.client.enableSessionTicketExtension",
	"jdk.security.enableTrustAnchorCertificates",
	"com.sun.org.apache.xalan.internal.xsltc.trax.TRANSLET_BYTECODE",
	"com.sun.org.apache.xalan.internal.xsltc.trax.DISABLE_TRANSLET_MAX_INLINE",
	"log4j.configurationFile",
	"log4j.configuration",
	"log4j2.configurationFile",
	"org.apache.logging.log4j.core.config",
	"java.library.path",
	"sun.boot.library.path",
	"java.home",
	"java.ext.dirs",
	"java.endorsed.dirs",
	"sun.boot.class.path",
	"java.class.path",
	"jdk.attach.allowAttachSelf",
	"jdk.attach.allowAttachMechanism",
	"java.class.loader.disableClassLoaderId",
	"com.sun.management.jmxremote.registry.ssl",
	"com.sun.management.jmxremote.password.file",
	"com.sun.management.jmxremote.access.file",
	"java.io.tmpdir",
	"hadoop.home.dir",
	"java.util.prefs.PreferencesFactory",
}

var JADWarn = []string{
	"http.proxyHost",
	"http.proxyPort",
	"https.proxyHost",
	"https.proxyPort",
	"ftp.proxyHost",
	"ftp.proxyPort",
	"socksProxyHost",
	"socksProxyPort",
	"http.nonProxyHosts",
	"ftp.nonProxyHosts",
	"socksNonProxyHosts",
	"java.net.useSystemProxies",
	"sun.net.inetaddr.ttl",
	"networkaddress.cache.ttl",
	"networkaddress.cache.negative.ttl",
	"sun.net.client.defaultConnectTimeout",
	"sun.net.client.defaultReadTimeout",
	"jdk.http.auth.tunneling.disabledSchemes",
	"jdk.http.auth.proxying.disabledSchemes",
	"http.auth.preference",
	"http.agent",
	"http.keepAlive",
	"http.maxConnections",
	"sun.net.http.errorstream.enableBuffering",
	"https.cipherSuites",
	"jsse.cipher.suites",
	"javax.net.debug",
	"jsse.enableSNIExtension",
	"jsse.enableMFLNExtension",
	"jdk.tls.client.cipherSuites",
	"jdk.tls.server.cipherSuites",
	"jdk.tls.acknowledgeCloseNotify",
	"jdk.tls.useExtendedMasterSecret",
	"jdk.tls.client.SNIHostname",
	"sun.security.ssl.skt",
	"jdk.httpserver.maxConnections",
	"jdk.httpclient.allowRestrictedHeaders",
	"jdk.httpclient.enableRealCB",
	"jdk.internal.httpclient.disableRetry",
	"jdk.http.ntlm.transparentAuth",
	"jdk.net.hosts.file",
	"jdk.net.unixdomain.tmpdir",
	"sun.net.dns.resolve.aadns",
	"jdk.serialFilter",
	"jdk.jfr.thread.dump.lockingMonitors",
	"sun.rmi.transport.tcp.responseTimeout",
	"sun.rmi.registry.registryFilter",
	"sun.rmi.transport.dgcFilter",
	"sun.rmi.transport.filter",
	"java.rmi.server.codebase",
	"java.rmi.server.useCodebaseOnly",
	"java.rmi.server.classLoader",
	"sun.jdbc.odbc.JdbcOdbcDriver",
	"com.mysql.allowLoadLocalInfile",
	"org.postgresql.allowEncodingChanges",
	"jdk.xml.entityExpansionLimit",
	"jdk.xml.maxGeneralEntitySizeLimit",
	"jdk.xml.maxParameterEntitySizeLimit",
	"jdk.xml.entityReplacementLimit",
	"jdk.xml.totalEntitySizeLimit",
	"javax.xml.accessExternalDTD",
	"javax.xml.accessExternalSchema",
	"javax.xml.accessExternalStylesheet",
	"javax.xml.isSupportingExternalEntities",
}

var JADAllow = []string{
	"file.encoding",
	"sun.jnu.encoding",
	"stdout.encoding",
	"stderr.encoding",
	"native.encoding",
	"sun.stdout.encoding",
	"sun.stderr.encoding",
	"user.timezone",
	"user.country",
	"user.language",
	"user.variant",
	"user.region",
	"user.home",
	"user.dir",
	"user.name",
	"java.awt.headless",
	"java.awt.graphicsenv",
	"java.awt.toolkit",
	"java.awt.fonts",
	"java.specification.version",
	"java.version",
	"java.runtime.version",
	"java.vm.version",
	"java.class.version",
	"os.name",
	"os.arch",
	"os.version",
	"line.separator",
	"path.separator",
	"file.separator",
	"sun.arch.data.model",
	"sun.cpu.endian",
	"sun.cpu.isalist",
	"sun.os.patch.level",
	"sun.io.unicode.encoding",
	"sun.java.launcher",
	"sun.management.compiler",
	"java.util.concurrent.ForkJoinPool.common.parallelism",
	"java.net.preferIPv4Stack",
	"java.net.preferIPv6Addresses",
	"jdk.virtualThreadScheduler.parallelism",
	"jdk.virtualThreadScheduler.maxPoolSize",
	"jdk.traceLauncher",
	"java.util.logging.config.file",
	"java.util.logging.manager",
	"app.name",
	"app.pid",
}

var JADPrefixLit = []string{
}
var JADPrefixReason = []string{
}

// JADFinding 表示一条命中。
type JADFinding struct {
	Reason string
	Detail string
}

// JADResult 是审计结果。
type JADResult struct {
	Safe bool
	Findings []JADFinding
}

func JADLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func JADIn(list []string, v string) bool {
	for _, x := range list { if JADLower(x) == v { return true } }
	return false
}

func JADSplit(in string) []string {
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

func JADKeyPart(tok string) string {
	t := tok
	if len(t) >= 2 && t[0] == '-' && (t[1] == 'D' || t[1] == 'd') { t = t[2:] }
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// JADHas 判定结果是否含某原因。
func JADHas(r JADResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// JADAudit 审计输入字符串。
func JADAudit(in string) JADResult {
	res := JADResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, JADFinding{Reason: JADReasonEmpty}); return res }
	toks := JADSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := JADLower(tok)
		key := JADKeyPart(cmp)
		switch {
		case JADIn(JADBlock, key):
			res.Findings = append(res.Findings, JADFinding{Reason: JADReasonBlock, Detail: key})
		case JADIn(JADWarn, key):
			res.Findings = append(res.Findings, JADFinding{Reason: JADReasonWarn, Detail: key})
		}
		for i, lit := range JADPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, JADFinding{Reason: JADPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
