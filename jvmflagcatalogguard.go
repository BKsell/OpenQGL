package main

// jvmflagcatalogguard.go —— JVM 启动标志风险目录与判定。
//
// 威胁模型：
//   启动器透传用户/整合包提供的 JVM 参数。危险标志可关闭字节码校验、附加 agent/本地库、在 OOM/错误时
//   执行系统命令、提升引导类路径注入恶意类、绕过 JPMS 封装。本模块对参数列表做纯判定（精确标志+危险前缀），
//   不实际启动 JVM，不使用正则。

// JVF 风险类别。
const (
	JVFClassBlock = "block"
	JVFClassWarn  = "warn"
	JVFClassAllow = "allow"
)

const (
	JVFReasonBlock   = "jvf-input-hits-blocked-catalog"
	JVFReasonWarn    = "jvf-input-hits-review-catalog"
	JVFReasonPrefix  = "jvf-input-hits-dangerous-prefix"
	JVFReasonEmpty   = "jvf-input-is-empty"
)

var JVFBlock = []string{
	"-Xverify:none",
	"-noverify",
	"-XX:+UnlockExperimentalVMOptions",
	"-XX:+EnableJVMTI",
	"-XX:+UnlockDiagnosticVMOptions",
	"-XX:+AllowRedefinitionToAddDeleteMethods",
	"-Xint",
	"-XX:+DisableAttachMechanism",
	"-Djava.security.manager=allow",
	"-Djava.security.manager=",
	"--enable-native-access=ALL-UNNAMED",
	"-XX:-UseCompressedOops",
	"-XX:+UseSerialGCWithForce",
}

var JVFWarn = []string{
	"-XX:+UseSerialGC",
	"-XX:ActiveProcessorCount=",
	"-XX:MaxRAMPercentage=",
	"-Xlog:",
	"-XX:StartFlightRecording=",
	"-XX:+FlightRecorder",
	"-Xshare:off",
	"-XX:-UsePerfData",
}

var JVFAllow = []string{
	"-Xmx",
	"-Xms",
	"-Xss",
	"-XX:+UseG1GC",
	"-XX:+UseZGC",
	"-XX:+UseShenandoahGC",
	"-XX:MaxMetaspaceSize=",
	"-XX:ParallelGCThreads=",
	"-Dfile.encoding=UTF-8",
	"-Duser.language=",
	"-XX:+UseStringDeduplication",
	"-XX:+HeapDumpOnOutOfMemoryError",
	"-XX:HeapDumpPath=",
	"-Dstdout.encoding=UTF-8",
	"-Dstderr.encoding=UTF-8",
	"-XX:+IgnoreUnrecognizedVMOptions",
	"-Dminecraft.launcher.brand=",
	"-XX:G1HeapRegionSize=",
	"-XX:+ExitOnOutOfMemoryError",
	"-XX:+AlwaysPreTouch",
	"-XX:+UseTransparentHugePages",
	"-Duser.country=",
	"-Duser.region=",
}

var JVFPrefixLit = []string{
	"-javaagent:",
	"-agentlib:",
	"-agentpath:",
	"-Xbootclasspath/a:",
	"-Xbootclasspath/p:",
	"-XX:OnOutOfMemoryError=",
	"-XX:OnError=",
	"--add-opens=",
	"--add-exports=",
	"--add-reads=",
	"--patch-module=",
	"-XX:NativeMemoryTracking=",
	"--enable-native-access=",
}
var JVFPrefixReason = []string{
	"jvm-flag-attaches-javaagent",
	"jvm-flag-loads-agent-library",
	"jvm-flag-loads-native-agent",
	"jvm-flag-extends-boot-classpath",
	"jvm-flag-prepends-boot-classpath",
	"jvm-flag-executes-command-on-oom",
	"jvm-flag-executes-command-on-error",
	"jvm-flag-breaks-module-encapsulation",
	"jvm-flag-exports-internal-api",
	"jvm-flag-adds-module-read-edge",
	"jvm-flag-patches-module-content",
	"jvm-flag-enables-native-memory-tracking",
	"jvm-flag-enables-native-access",
}

// JVFFinding 表示一条命中。
type JVFFinding struct {
	Reason string
	Detail string
}

// JVFResult 是审计结果。
type JVFResult struct {
	Safe bool
	Findings []JVFFinding
}

func JVFLower(x string) string {
	return x
}

func JVFIn(list []string, v string) bool {
	for _, x := range list { if JVFLower(x) == v { return true } }
	return false
}

func JVFSplit(in string) []string {
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

func JVFKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// JVFHas 判定结果是否含某原因。
func JVFHas(r JVFResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// JVFAudit 审计输入字符串。
func JVFAudit(in string) JVFResult {
	res := JVFResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, JVFFinding{Reason: JVFReasonEmpty}); return res }
	toks := JVFSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := JVFLower(tok)
		key := cmp
		switch {
		case JVFIn(JVFBlock, key):
			res.Findings = append(res.Findings, JVFFinding{Reason: JVFReasonBlock, Detail: key})
		case JVFIn(JVFWarn, key):
			res.Findings = append(res.Findings, JVFFinding{Reason: JVFReasonWarn, Detail: key})
		}
		for i, lit := range JVFPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, JVFFinding{Reason: JVFPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
