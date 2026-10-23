package main

// dockerflagcatalogguard.go —— Docker/容器危险启动标志目录。
//
// 威胁模型：
//   --privileged/--pid=host/--network=host/--cap-add=SYS_ADMIN/挂载 docker.sock 等标志等价宿主 root。纯字符查表，不用正则。

// DKF 风险类别。
const (
	DKFClassBlock = "block"
	DKFClassWarn  = "warn"
	DKFClassAllow = "allow"
)

const (
	DKFReasonBlock   = "dkf-input-hits-blocked-catalog"
	DKFReasonWarn    = "dkf-input-hits-review-catalog"
	DKFReasonPrefix  = "dkf-input-hits-dangerous-prefix"
	DKFReasonEmpty   = "dkf-input-is-empty"
)

var DKFBlock = []string{
	"--privileged",
	"--pid=host",
	"--network=host",
	"--net=host",
	"--ipc=host",
	"--uts=host",
	"--userns=host",
	"--cgroupns=host",
	"--cap-add=ALL",
	"--cap-add=SYS_ADMIN",
	"--cap-add=SYS_PTRACE",
	"--cap-add=SYS_MODULE",
	"--cap-add=DAC_OVERRIDE",
	"--cap-add=NET_ADMIN",
	"seccomp=unconfined",
	"apparmor=unconfined",
	"privileged",
	"/var/run/docker.sock",
	"--device=/dev/kmsg",
	"--device=/dev/mem",
	"--device=/dev/kcore",
}

var DKFWarn = []string{
	"--cap-add",
	"--cap-drop",
	"--security-opt",
	"--device",
	"--device-cgroup-rule",
	"-v",
	"--volume",
	"--mount",
	"--sysctl",
	"--tmpfs",
	"--add-host",
	"--kernel-memory",
	"--oom-kill-disable",
	"root",
	"type=bind",
	"--user",
	"-u",
}

var DKFAllow = []string{
	"--read-only",
	"--cap-drop=ALL",
	"no-new-privileges",
	"--init",
	"--pids-limit",
	"--memory",
	"--cpus",
	"--security-opt=no-new-privileges",
	"--tmpfs-size",
}

var DKFPrefixLit = []string{
}
var DKFPrefixReason = []string{
}

// DKFFinding 表示一条命中。
type DKFFinding struct {
	Reason string
	Detail string
}

// DKFResult 是审计结果。
type DKFResult struct {
	Safe bool
	Findings []DKFFinding
}

func DKFLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func DKFIn(list []string, v string) bool {
	for _, x := range list { if DKFLower(x) == v { return true } }
	return false
}

func DKFSplit(in string) []string {
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

func DKFKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// DKFHas 判定结果是否含某原因。
func DKFHas(r DKFResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// DKFAudit 审计输入字符串。
func DKFAudit(in string) DKFResult {
	res := DKFResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, DKFFinding{Reason: DKFReasonEmpty}); return res }
	toks := DKFSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := DKFLower(tok)
		key := cmp
		switch {
		case DKFIn(DKFBlock, key):
			res.Findings = append(res.Findings, DKFFinding{Reason: DKFReasonBlock, Detail: key})
		case DKFIn(DKFWarn, key):
			res.Findings = append(res.Findings, DKFFinding{Reason: DKFReasonWarn, Detail: key})
		}
		for i, lit := range DKFPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, DKFFinding{Reason: DKFPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
