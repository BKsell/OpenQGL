package main

// configfilesecretkeydirectoryguard.go —— 配置文件密钥键名目录。
//
// 威胁模型：
//   配置中 password/secret/token/api_key/private_key 明文落盘即风险，
//   应引用密钥管理或环境注入。纯字符查表，不用正则。

const (
	CFKClassBlock   = "block"
	CFKClassWarn    = "warn"
	CFKClassAllow   = "allow"
	CFKClassUnknown = "unknown"
)

var CFKBlock = []string{
	"password=",
	"secret=",
	"token=",
	"api_key=",
	"private_key=",
	"access_key=",
}

var CFKWarn = []string{
	"credentials=",
	"connectionstring=",
}

var CFKAllow = []string{
	"${vault}",
	"${env}",
}

func CFKLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CFKIn(list []string, v string) bool {
	for _, x := range list { if CFKLower(x) == v { return true } }
	return false
}

// CFKClassify 分类单个令牌。
func CFKClassify(tok string) string {
	v := CFKLower(tok)
	switch {
	case CFKIn(CFKBlock, v): return CFKClassBlock
	case CFKIn(CFKWarn, v): return CFKClassWarn
	case CFKIn(CFKAllow, v): return CFKClassAllow
	default: return CFKClassUnknown
	}
}
