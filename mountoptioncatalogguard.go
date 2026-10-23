package main

// mountoptioncatalogguard.go —— 危险挂载选项目录。
//
// 威胁模型：
//   suid/dev/exec/privileged/bind 宿主敏感路径等挂载选项可提权或逃逸。本目录按空格分隔选项精确匹配，纯字符，不用正则。

// MOC 风险类别。
const (
	MOCClassBlock = "block"
	MOCClassWarn  = "warn"
	MOCClassAllow = "allow"
)

const (
	MOCReasonBlock   = "moc-input-hits-blocked-catalog"
	MOCReasonWarn    = "moc-input-hits-review-catalog"
	MOCReasonPrefix  = "moc-input-hits-dangerous-prefix"
	MOCReasonEmpty   = "moc-input-is-empty"
)

var MOCBlock = []string{
	"suid",
	"dev",
	"privileged",
	"rshared",
	"shared",
	"rslave",
	"rprivate",
	"unbindable",
	"make-shared",
	"make-rshared",
	"make-slave",
	"make-rslave",
	"make-private",
	"make-rprivate",
	"make-unbindable",
}

var MOCWarn = []string{
	"nosuid",
	"nodev",
	"noexec",
	"ro",
	"rw",
	"bind",
	"rbind",
	"remount",
	"mand",
	"nomand",
	"noauto",
	"user",
	"nouser",
	"users",
	"owner",
	"group",
	"exec",
	"devtmpfs",
	"tmpfs",
	"overlay",
}

var MOCAllow = []string{
	"defaults",
	"relatime",
	"noatime",
	"strictatime",
	"sync",
	"async",
	"dirsync",
	"noacl",
	"iversion",
	"noiversion",
	"_netdev",
	"quiet",
	"nofail",
	"loop",
	"comment",
	"umask",
	"dmask",
	"fmask",
	"uid",
	"gid",
	"flush",
	"x-systemd.automount",
	"x-systemd.device-bound",
	"x-systemd.makefs",
}

var MOCPrefixLit = []string{
}
var MOCPrefixReason = []string{
}

// MOCFinding 表示一条命中。
type MOCFinding struct {
	Reason string
	Detail string
}

// MOCResult 是审计结果。
type MOCResult struct {
	Safe bool
	Findings []MOCFinding
}

func MOCLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func MOCIn(list []string, v string) bool {
	for _, x := range list { if MOCLower(x) == v { return true } }
	return false
}

func MOCSplit(in string) []string {
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

func MOCKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// MOCHas 判定结果是否含某原因。
func MOCHas(r MOCResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// MOCAudit 审计输入字符串。
func MOCAudit(in string) MOCResult {
	res := MOCResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, MOCFinding{Reason: MOCReasonEmpty}); return res }
	toks := MOCSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := MOCLower(tok)
		key := cmp
		switch {
		case MOCIn(MOCBlock, key):
			res.Findings = append(res.Findings, MOCFinding{Reason: MOCReasonBlock, Detail: key})
		case MOCIn(MOCWarn, key):
			res.Findings = append(res.Findings, MOCFinding{Reason: MOCReasonWarn, Detail: key})
		}
		for i, lit := range MOCPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, MOCFinding{Reason: MOCPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
