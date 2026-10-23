package main

// jvmoptiondirectoryguard.go —— JVM/HotSpot 启动选项风险目录。
//
// 威胁模型：
//   启动器透传 JVM 参数。本目录按危险（禁校验/agent/执行命令/模块封装突破）、需复核（内存/GC/调试）、
//   常规（编码/品牌/堆参数）对 HotSpot/JPMS 选项分级，精确标志匹配，不启动 JVM，不用正则。

// JOD 风险类别。
const (
	JODClassBlock = "block"
	JODClassWarn  = "warn"
	JODClassAllow = "allow"
)

const (
	JODReasonBlock   = "jod-input-hits-blocked-catalog"
	JODReasonWarn    = "jod-input-hits-review-catalog"
	JODReasonPrefix  = "jod-input-hits-dangerous-prefix"
	JODReasonEmpty   = "jod-input-is-empty"
)

var JODBlock = []string{
	"-verify",
	"-Xverify:none",
	"-Xverify:none:all",
	"-noverify",
	"-Xfuture",
	"-XX:-BytecodeVerificationRemote",
	"-XX:-BytecodeVerificationLocal",
	"-javaagent",
	"-agentlib",
	"-agentpath",
	"-J-javaagent",
	"-J-agentlib",
	"-J-agentpath",
	"-XX:OnError",
	"-XX:OnOutOfMemoryError",
	"-XX:+ExecuteInternalVMTests",
	"-XX:+UnlockDiagnosticVMOptions",
	"-XX:+PrintCommandLineFlags",
	"-Xlog",
	"-Xbootclasspath",
	"-Xbootclasspath/a",
	"-Xbootclasspath/p",
	"-Xbootclasspath/c",
	"-endorseddirs",
	"-Djava.endorsed.dirs",
	"-Djava.ext.dirs",
	"-Dsun.boot.library.path",
	"-Djava.library.path",
	"-Djava.home",
	"-Dsun.java.command",
	"--add-opens",
	"--add-exports",
	"--add-reads",
	"--patch-module",
	"--upgrade-module-path",
	"--limit-modules",
	"--enable-native-access",
	"--enable-preview",
	"--source",
	"--target",
	"-Dcom.sun.management.jmxremote",
	"-Dcom.sun.management.jmxremote.port",
	"-Dcom.sun.management.jmxremote.authenticate",
	"-Dcom.sun.management.jmxremote.ssl",
	"-Dcom.sun.management.jmxremote.local.only",
	"-Dcom.sun.management.jmxremote.rmi.port",
	"-Djava.rmi.server.hostname",
	"-Djava.security.manager",
	"-Djava.security.policy",
	"-Djava.security.egd",
	"-Djava.security.properties",
	"-Djavax.net.ssl.trustStore",
	"-Djavax.net.ssl.trustStorePassword",
	"-Djavax.net.ssl.keyStore",
	"-Djavax.net.ssl.keyStorePassword",
	"-Djdk.tls.client.protocols",
	"-Dhttps.protocols",
	"-Djdk.tls.disabledAlgorithms",
	"-Djava.security.disabledAlgorithms",
	"-Dcom.sun.net.ssl.checkRevocation",
	"-Dcom.sun.jndi.ldap.object.trustURLCodebase",
	"-Dcom.sun.jndi.rmi.object.trustURLCodebase",
	"-Dcom.sun.jndi.cosnaming.object.trustURLCodebase",
	"-Djava.naming.factory.initial",
	"-Djava.naming.provider.url",
	"-Djdk.jndi.object.factoriesFilter",
	"-Dlog4j.configurationFile",
	"-Dlog4j2.formatMsgNoLookups",
	"-Dlog4j.configuration",
	"-Dorg.apache.logging.log4j.core.config",
	"-Dsun.tools.jar.disableMultiRelease",
	"-Djdk.attach.allowAttachSelf",
	"-Djdk.attach.allowAttachMechanism",
	"-Djdk.lang.Process.launchMechanism",
	"-XX:+UseAltSigs",
	"-XX:+AllowRedefinitionToAddDeleteMethods",
	"-XX:+EnableDynamicAgentLoading",
	"-XX:+RelaxAccessControlCheck",
	"-XX:+UseSerialGC",
}

var JODWarn = []string{
	"-Xms",
	"-Xmx",
	"-Xss",
	"-Xmn",
	"-Xoss",
	"-XX:MaxMetaspaceSize",
	"-XX:MetaspaceSize",
	"-XX:MaxDirectMemorySize",
	"-XX:InitialRAMPercentage",
	"-XX:MaxRAMPercentage",
	"-XX:MinRAMPercentage",
	"-XX:+UseG1GC",
	"-XX:+UseParallelGC",
	"-XX:+UseZGC",
	"-XX:+UseShenandoahGC",
	"-XX:+UseConcMarkSweepGC",
	"-XX:ParallelGCThreads",
	"-XX:ConcGCThreads",
	"-XX:MaxGCPauseMillis",
	"-XX:GCTimeRatio",
	"-XX:+UseStringDeduplication",
	"-XX:+UseCompressedOops",
	"-XX:+UseCompressedClassPointers",
	"-XX:+AggressiveOpts",
	"-XX:+AggressiveHeap",
	"-XX:+AlwaysPreTouch",
	"-XX:+UseNUMA",
	"-XX:+UseLargePages",
	"-XX:LargePageSizeInBytes",
	"-XX:+UseTransparentHugePages",
	"-XX:SoftRefLRUPolicyMSPerms",
	"-XX:MaxTenuringThreshold",
	"-XX:SurvivorRatio",
	"-XX:NewRatio",
	"-XX:NewSize",
	"-XX:+PrintGC",
	"-XX:+PrintGCDetails",
	"-XX:+PrintGCDateStamps",
	"-Xlog:gc",
	"-Xlog:gc*",
	"-verbose:gc",
	"-XX:+HeapDumpOnOutOfMemoryError",
	"-XX:HeapDumpPath",
	"-XX:+ExitOnOutOfMemoryError",
	"-XX:+CrashOnOutOfMemoryError",
	"-XX:ErrorFile",
	"-XX:+FlightRecorder",
	"-XX:StartFlightRecording",
	"-XX:+UnlockCommercialFeatures",
	"-Xdebug",
	"-Xrunjdwp",
	"-agentlib:jdwp",
	"-Xnoagent",
	"-Xrunjdwp:transport",
	"-Xrunjdwp:server",
	"-Xrunjdwp:suspend",
	"-Xrunjdwp:address",
	"-Djava.compiler",
	"-Djava.awt.headless",
	"-Dfile.encoding",
	"-Dsun.jnu.encoding",
	"-Duser.timezone",
	"-Duser.country",
	"-Duser.language",
	"-Duser.variant",
	"-Dhttp.proxyHost",
	"-Dhttp.proxyPort",
	"-Dhttps.proxyHost",
	"-Dhttps.proxyPort",
	"-Dftp.proxyHost",
	"-DsocksProxyHost",
	"-DsocksProxyPort",
	"-Dhttp.nonProxyHosts",
	"-Djava.net.useSystemProxies",
	"-Dsun.net.inetaddr.ttl",
	"-Dnetworkaddress.cache.ttl",
	"-Djdk.http.auth.tunneling.disabledSchemes",
	"-Djdk.http.auth.proxying.disabledSchemes",
	"-Dsun.net.client.defaultConnectTimeout",
	"-Dsun.net.client.defaultReadTimeout",
	"-Djdk.tls.ephemeralDHKeySize",
	"-Djdk.tls.rejectClientInitiatedRenegotiation",
	"-Djdk.tls.allowUnsafeServerCertChange",
	"-Dsun.security.ssl.allowUnsafeRenegotiation",
	"-Dsun.security.ssl.allowLegacyHelloMessages",
	"-Djsse.enableSNIExtension",
	"-Djsse.enableMFLNExtension",
	"-Djsse.cipher.suites",
	"-Dhttps.cipherSuites",
	"-Djavax.net.debug",
	"-Dcom.sun.xml.ws.transport.http.client.HttpTransportPipe.dump",
	"-Xdock:name",
	"-Xdock:icon",
	"-XstartOnFirstThread",
	"-XstartOnMinThread",
	"-Djava.awt.graphicsenv",
	"-Dprism.order",
	"-Dprism.verbose",
	"-Djavafx.platform",
	"-Dglass.platform",
	"-Djava.class.path",
	"-cp",
	"-classpath",
	"--class-path",
	"--module-path",
	"-p",
	"-m",
	"--module",
	"--source-path",
	"-d",
	"-encoding",
	"-source",
	"-version",
	"-showversion",
	"-help",
	"-?",
	"-X",
	"-Djava.io.tmpdir",
	"-Djava.util.logging.config.file",
	"-Djava.util.logging.config.class",
	"-Dsun.stdout.encoding",
	"-Dsun.stderr.encoding",
	"-Dstdout.encoding",
	"-Dstderr.encoding",
	"-Dnative.encoding",
	"-Dsun.stdout.err",
}

var JODAllow = []string{
	"-server",
	"-client",
	"-d64",
	"-d32",
	"-jar",
	"-jre-restrict-search",
	"-Djava.specification.version",
	"-Djava.version",
	"-Djava.vm.version",
	"-Djava.runtime.version",
	"-Djava.vendor",
	"-Djava.vm.vendor",
	"-Djava.vm.name",
	"-Dos.name",
	"-Dos.arch",
	"-Dos.version",
	"-Dline.separator",
	"-Dpath.separator",
	"-Dfile.separator",
	"-Duser.home",
	"-Duser.dir",
	"-Duser.name",
	"-Djava.class.version",
	"-Djava.specification.name",
	"-Djava.specification.vendor",
	"-Djava.vm.specification.name",
	"-Djava.vm.specification.vendor",
	"-Djava.vm.specification.version",
	"-Djava.runtime.name",
	"-Djava.endorsed",
	"-Dsun.arch.data.model",
	"-Dsun.cpu.endian",
	"-Dsun.cpu.isalist",
	"-Dsun.os.patch.level",
	"-Dsun.io.unicode.encoding",
	"-Dsun.java.launcher",
	"-Dsun.management.compiler",
	"-Dsun.boot.class.path",
	"-Djava.util.concurrent.ForkJoinPool.common.parallelism",
	"-Djava.net.preferIPv4Stack",
	"-Djava.net.preferIPv6Addresses",
	"-Djdk.virtualThreadScheduler.parallelism",
	"-Djdk.virtualThreadScheduler.maxPoolSize",
	"-XX:+DisableAttachMechanism",
	"-XX:+UseContainerSupport",
	"-XX:ActiveProcessorCount",
	"-XX:-UseContainerSupport",
	"--enable-native-access=none",
	"--illegal-access=deny",
	"--illegal-native-access=deny",
	"-XX:+PreserveFramePointer",
	"-XX:-OmitStackTraceInFastThrow",
	"-XX:+StackTraceInThrowable",
}

var JODPrefixLit = []string{
}
var JODPrefixReason = []string{
}

// JODFinding 表示一条命中。
type JODFinding struct {
	Reason string
	Detail string
}

// JODResult 是审计结果。
type JODResult struct {
	Safe bool
	Findings []JODFinding
}

func JODLower(x string) string {
	return x
}

func JODIn(list []string, v string) bool {
	for _, x := range list { if JODLower(x) == v { return true } }
	return false
}

func JODSplit(in string) []string {
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

func JODKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// JODHas 判定结果是否含某原因。
func JODHas(r JODResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// JODAudit 审计输入字符串。
func JODAudit(in string) JODResult {
	res := JODResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, JODFinding{Reason: JODReasonEmpty}); return res }
	toks := JODSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := JODLower(tok)
		key := cmp
		switch {
		case JODIn(JODBlock, key):
			res.Findings = append(res.Findings, JODFinding{Reason: JODReasonBlock, Detail: key})
		case JODIn(JODWarn, key):
			res.Findings = append(res.Findings, JODFinding{Reason: JODReasonWarn, Detail: key})
		}
		for i, lit := range JODPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, JODFinding{Reason: JODPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
