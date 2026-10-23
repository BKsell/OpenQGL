package main

// embeddedsecretfilenamedirectoryguard.go —— 镜像/包内嵌密钥文件名目录。
//
// 威胁模型：
//   .env、id_rsa、*.pem、.keystore、credentials 被打进镜像或分发包会泄露私钥，
//   应通过 .dockerignore/.gitignore 排除。纯字符查表，不用正则。

const (
	EFSClassBlock   = "block"
	EFSClassWarn    = "warn"
	EFSClassAllow   = "allow"
	EFSClassUnknown = "unknown"
)

var EFSBlock = []string{
	".env",
	"id_rsa",
	".pem",
	".keystore",
	"credentials",
	".netrc",
	".htpasswd",
}

var EFSWarn = []string{
	".npmrc",
	".pypirc",
}

var EFSAllow = []string{
	".env.example",
}

func EFSLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func EFSIn(list []string, v string) bool {
	for _, x := range list { if EFSLower(x) == v { return true } }
	return false
}

// EFSClassify 分类单个令牌。
func EFSClassify(tok string) string {
	v := EFSLower(tok)
	switch {
	case EFSIn(EFSBlock, v): return EFSClassBlock
	case EFSIn(EFSWarn, v): return EFSClassWarn
	case EFSIn(EFSAllow, v): return EFSClassAllow
	default: return EFSClassUnknown
	}
}
