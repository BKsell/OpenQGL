package main

// envvarcatalogguard.go —— 敏感环境变量名目录。
//
// 威胁模型：
//   子进程继承环境块。变量名携带令牌/密钥，或可劫持 DLL/JNI/native 加载路径、代理、JVM 选项，
//   均需在 spawn 前审计/清洗。本模块维护敏感变量名目录，纯字符判定，不读取真实环境，不用正则。

// EVC 风险类别。
const (
	EVCClassBlock = "block"
	EVCClassWarn  = "warn"
	EVCClassAllow = "allow"
)

const (
	EVCReasonBlock   = "evc-input-hits-blocked-catalog"
	EVCReasonWarn    = "evc-input-hits-review-catalog"
	EVCReasonPrefix  = "evc-input-hits-dangerous-prefix"
	EVCReasonEmpty   = "evc-input-is-empty"
)

var EVCBlock = []string{
	"JAVA_TOOL_OPTIONS",
	"JDK_JAVA_OPTIONS",
	"_JAVA_OPTIONS",
	"JPDA_OPTS",
	"LD_PRELOAD",
	"DYLD_INSERT_LIBRARIES",
	"NODE_OPTIONS",
	"NODE_EXTRA_CA_CERTS",
	"NODE_TLS_REJECT_UNAUTHORIZED",
	"SSL_CERT_FILE",
	"SSL_CERT_DIR",
	"REQUESTS_CA_BUNDLE",
	"CURL_CA_BUNDLE",
	"GIT_SSH_COMMAND",
	"BASH_ENV",
	"IDEA_VM_OPTIONS",
	"JAVA_RANDOM_OPTIONS",
}

var EVCWarn = []string{
	"LD_LIBRARY_PATH",
	"DYLD_LIBRARY_PATH",
	"GIT_SSH",
	"JAVA_OPTS",
	"JVM_OPTS",
	"PATH",
	"PATHEXT",
	"JAVA_HOME",
	"JRE_HOME",
	"CLASSPATH",
	"HTTP_PROXY",
	"HTTPS_PROXY",
	"ALL_PROXY",
	"NO_PROXY",
	"http_proxy",
	"https_proxy",
	"all_proxy",
	"no_proxy",
	"FTP_PROXY",
	"SOCKS_PROXY",
	"TEMP",
	"TMP",
	"TMPDIR",
}

var EVCAllow = []string{
	"LANG",
	"LC_ALL",
	"TZ",
	"COMPUTERNAME",
	"NUMBER_OF_PROCESSORS",
	"OS",
	"SYSTEMDRIVE",
	"SYSTEMROOT",
	"WINDIR",
	"PUBLIC",
	"ProgramData",
	"USERNAME",
	"PROCESSOR_ARCHITECTURE",
	"APPDATA",
	"LOCALAPPDATA",
}

var EVCPrefixLit = []string{
	"TOKEN",
	"SECRET",
	"PASSWORD",
	"PRIVATE_KEY",
	"API_KEY",
	"ACCESS_KEY",
	"CREDENTIAL",
}
var EVCPrefixReason = []string{
	"env-name-may-contain-token",
	"env-name-may-contain-secret",
	"env-name-may-contain-password",
	"env-name-may-contain-private-key",
	"env-name-may-contain-api-key",
	"env-name-may-contain-access-key",
	"env-name-may-contain-credential",
}

// EVCFinding 表示一条命中。
type EVCFinding struct {
	Reason string
	Detail string
}

// EVCResult 是审计结果。
type EVCResult struct {
	Safe bool
	Findings []EVCFinding
}

func EVCLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func EVCIn(list []string, v string) bool {
	for _, x := range list { if EVCLower(x) == v { return true } }
	return false
}

func EVCSplit(in string) []string {
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

func EVCKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// EVCHas 判定结果是否含某原因。
func EVCHas(r EVCResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// EVCAudit 审计输入字符串。
func EVCAudit(in string) EVCResult {
	res := EVCResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, EVCFinding{Reason: EVCReasonEmpty}); return res }
	toks := EVCSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := EVCLower(tok)
		key := cmp
		switch {
		case EVCIn(EVCBlock, key):
			res.Findings = append(res.Findings, EVCFinding{Reason: EVCReasonBlock, Detail: key})
		case EVCIn(EVCWarn, key):
			res.Findings = append(res.Findings, EVCFinding{Reason: EVCReasonWarn, Detail: key})
		}
		for i, lit := range EVCPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, EVCFinding{Reason: EVCPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
