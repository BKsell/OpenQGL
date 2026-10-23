package main

// systemdunitdirectivecatalogguard.go —— systemd unit 危险指令目录。
//
// 威胁模型：
//   ExecStartPost/ExecStartPre 写绝对命令、User=root、NoNewPrivileges=false、ProtectSystem 关闭等削弱沙箱。纯字符查表，不用正则。

// SUD 风险类别。
const (
	SUDClassBlock = "block"
	SUDClassWarn  = "warn"
	SUDClassAllow = "allow"
)

const (
	SUDReasonBlock   = "sud-input-hits-blocked-catalog"
	SUDReasonWarn    = "sud-input-hits-review-catalog"
	SUDReasonPrefix  = "sud-input-hits-dangerous-prefix"
	SUDReasonEmpty   = "sud-input-is-empty"
)

var SUDBlock = []string{
	"ExecStartPre",
	"ExecStartPost",
	"ExecStopPost",
	"ExecReload",
	"ExecCondition",
	"NoNewPrivileges=false",
	"ProtectSystem=false",
	"ProtectHome=false",
	"PrivateTmp=false",
	"PrivateDevices=false",
	"ProtectKernelTunables=false",
	"ProtectKernelModules=false",
	"ProtectControlGroups=false",
	"MemoryDenyWriteExecute=false",
	"RestrictSUIDSGID=false",
}

var SUDWarn = []string{
	"ExecStart",
	"ExecStop",
	"User",
	"Group",
	"WorkingDirectory",
	"RootDirectory",
	"RootImage",
	"Environment",
	"EnvironmentFile",
	"PassEnvironment",
	"UnsetEnvironment",
	"StandardInput",
	"StandardOutput",
	"StandardError",
	"TTYPath",
	"PAMName",
	"SupplementaryGroups",
	"LoadCredential",
	"SetCredential",
	"SetCredentialEncrypted",
	"Delegate",
	"NotifyAccess",
	"Sockets",
	"KillMode",
	"KillSignal",
	"Restart",
	"RestartSec",
	"UMask",
	"SELinuxContext",
	"AppArmorProfile",
	"SmackProcessLabel",
	"ReadWritePaths",
	"BindPaths",
	"DeviceAllow",
	"DevicePolicy",
	"OOMScoreAdjust",
}

var SUDAllow = []string{
	"NoNewPrivileges",
	"ProtectSystem",
	"ProtectHome",
	"PrivateTmp",
	"PrivateDevices",
	"PrivateNetwork",
	"PrivateUsers",
	"PrivateMounts",
	"ProtectKernelTunables",
	"ProtectKernelModules",
	"ProtectKernelLogs",
	"ProtectControlGroups",
	"ProtectClock",
	"ProtectHostname",
	"ProtectProc",
	"RestrictAddressFamilies",
	"RestrictNamespaces",
	"RestrictRealtime",
	"RestrictSUIDSGID",
	"LockPersonality",
	"MemoryDenyWriteExecute",
	"SystemCallFilter",
	"SystemCallArchitectures",
	"CapabilityBoundingSet",
	"AmbientCapabilities",
	"RemoveIPC",
	"DynamicUser",
	"ReadOnlyPaths",
	"InaccessiblePaths",
	"BindReadOnlyPaths",
	"ResourceLimits",
}

var SUDPrefixLit = []string{
}
var SUDPrefixReason = []string{
}

// SUDFinding 表示一条命中。
type SUDFinding struct {
	Reason string
	Detail string
}

// SUDResult 是审计结果。
type SUDResult struct {
	Safe bool
	Findings []SUDFinding
}

func SUDLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func SUDIn(list []string, v string) bool {
	for _, x := range list { if SUDLower(x) == v { return true } }
	return false
}

func SUDSplit(in string) []string {
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

func SUDKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// SUDHas 判定结果是否含某原因。
func SUDHas(r SUDResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// SUDAudit 审计输入字符串。
func SUDAudit(in string) SUDResult {
	res := SUDResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, SUDFinding{Reason: SUDReasonEmpty}); return res }
	toks := SUDSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := SUDLower(tok)
		key := cmp
		switch {
		case SUDIn(SUDBlock, key):
			res.Findings = append(res.Findings, SUDFinding{Reason: SUDReasonBlock, Detail: key})
		case SUDIn(SUDWarn, key):
			res.Findings = append(res.Findings, SUDFinding{Reason: SUDReasonWarn, Detail: key})
		}
		for i, lit := range SUDPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, SUDFinding{Reason: SUDPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
