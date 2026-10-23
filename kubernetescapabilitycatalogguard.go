package main

// kubernetescapabilitycatalogguard.go —— Kubernetes 安全相关字段目录。
//
// 威胁模型：
//   privileged/hostPID/hostNetwork/hostPath/allowPrivilegeEscalation/runAsRoot 与 :latest/默认 SA 挂载需管控。纯字符查表，不用正则。

const (
	K8SClassBlock   = "block"
	K8SClassWarn    = "warn"
	K8SClassAllow   = "allow"
	K8SClassUnknown = "unknown"
)

var K8SBlock = []string{
	"privileged",
	"hostPID",
	"hostIPC",
	"hostNetwork",
	"hostPath",
	"allowPrivilegeEscalation",
	"latest",
	"SYS_ADMIN",
	"NET_ADMIN",
	"DAC_OVERRIDE",
	"UnmaskedProcMount",
}

var K8SWarn = []string{
	"runAsUser",
	"runAsGroup",
	"fsGroup",
	"supplementalGroups",
	"sysctls",
	"capabilities",
	"seccompProfile",
	"apparmor",
	"seLinuxOptions",
	"procMount",
	"hostPorts",
	"hostAliases",
	"nodeName",
	"automountServiceAccountToken",
	"subPath",
	"CAP_NET_RAW",
}

var K8SAllow = []string{
	"RuntimeDefault",
	"Localhost",
	"MustRunAs",
	"MustRunAsNonRoot",
	"runAsNonRoot",
	"readOnly",
}

func K8SLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func K8SIn(list []string, v string) bool {
	for _, x := range list { if K8SLower(x) == v { return true } }
	return false
}

// K8SClassify 分类单个令牌。
func K8SClassify(tok string) string {
	v := K8SLower(tok)
	switch {
	case K8SIn(K8SBlock, v): return K8SClassBlock
	case K8SIn(K8SWarn, v): return K8SClassWarn
	case K8SIn(K8SAllow, v): return K8SClassAllow
	default: return K8SClassUnknown
	}
}
