package main

// kubernetesecretmountdirectoryguard.go —— K8s Secret 挂载风险目录。
//
// 威胁模型：
//   Secret 以环境变量明文注入、卷挂载默认权限或 etcd 未加密会暴露令牌，
//   应 projected 卷 0400 且 etcd 加密。纯字符查表，不用正则。

const (
	KSEClassBlock   = "block"
	KSEClassWarn    = "warn"
	KSEClassAllow   = "allow"
	KSEClassUnknown = "unknown"
)

var KSEBlock = []string{
	"secretkeyref-default",
	"secret-volume-world",
	"etcd-plaintext",
	"env-secret",
}

var KSEWarn = []string{
	"projected-default",
}

var KSEAllow = []string{
	"mounted-0400",
	"etcd-encrypted",
}

func KSELower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func KSEIn(list []string, v string) bool {
	for _, x := range list { if KSELower(x) == v { return true } }
	return false
}

// KSEClassify 分类单个令牌。
func KSEClassify(tok string) string {
	v := KSELower(tok)
	switch {
	case KSEIn(KSEBlock, v): return KSEClassBlock
	case KSEIn(KSEWarn, v): return KSEClassWarn
	case KSEIn(KSEAllow, v): return KSEClassAllow
	default: return KSEClassUnknown
	}
}
