package main

// linuxcapabilitycatalogguard.go —— Linux capabilities 特权目录。
//
// 威胁模型：
//   CAP_SYS_ADMIN/CAP_DAC_OVERRIDE/CAP_NET_RAW/CAP_SETUID 等权能近似 root，容器默认应丢弃。纯字符查表，不用正则。

const (
	CAPClassBlock   = "block"
	CAPClassWarn    = "warn"
	CAPClassAllow   = "allow"
	CAPClassUnknown = "unknown"
)

var CAPBlock = []string{
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_MODULE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_PTRACE",
	"CAP_SYS_CHROOT",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_SETUID",
	"CAP_SETGID",
	"CAP_SETFCAP",
	"CAP_NET_ADMIN",
	"CAP_NET_RAW",
	"CAP_MAC_ADMIN",
	"CAP_MAC_OVERRIDE",
	"CAP_SYSLOG",
	"CAP_BPF",
	"CAP_PERFMON",
	"CAP_CHECKPOINT_RESTORE",
	"CAP_AUDIT_CONTROL",
	"CAP_LINUX_IMMUTABLE",
	"CAP_IPC_LOCK",
	"CAP_IPC_OWNER",
	"CAP_MKNOD",
	"CAP_BLOCK_SUSPEND",
	"CAP_WAKE_ALARM",
	"CAP_SETPCAP",
}

var CAPWarn = []string{
	"CAP_KILL",
	"CAP_CHOWN",
	"CAP_NET_BROADCAST",
	"CAP_LEASE",
	"CAP_AUDIT_WRITE",
	"CAP_AUDIT_READ",
	"CAP_SYS_NICE",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG",
	"CAP_SYS_PACCT",
}

var CAPAllow = []string{
	"CAP_NET_BIND_SERVICE",
}

func CAPLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CAPIn(list []string, v string) bool {
	for _, x := range list { if CAPLower(x) == v { return true } }
	return false
}

// CAPClassify 分类单个令牌。
func CAPClassify(tok string) string {
	v := CAPLower(tok)
	switch {
	case CAPIn(CAPBlock, v): return CAPClassBlock
	case CAPIn(CAPWarn, v): return CAPClassWarn
	case CAPIn(CAPAllow, v): return CAPClassAllow
	default: return CAPClassUnknown
	}
}
