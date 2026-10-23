package main

// pkcechallengemethoddirectoryguard.go —— PKCE code_challenge_method 目录。
//
// 威胁模型：
//   plain 方法不绑定挑战，授权码截获即可换令牌，
//   必须 S256。纯字符查表，不用正则。

const (
	PK2ClassBlock   = "block"
	PK2ClassWarn    = "warn"
	PK2ClassAllow   = "allow"
	PK2ClassUnknown = "unknown"
)

var PK2Block = []string{
	"plain",
	"",
}

var PK2Warn = []string{
	"s256-missing",
}

var PK2Allow = []string{
	"s256",
}

func PK2Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func PK2In(list []string, v string) bool {
	for _, x := range list { if PK2Lower(x) == v { return true } }
	return false
}

// PK2Classify 分类单个令牌。
func PK2Classify(tok string) string {
	v := PK2Lower(tok)
	switch {
	case PK2In(PK2Block, v): return PK2ClassBlock
	case PK2In(PK2Warn, v): return PK2ClassWarn
	case PK2In(PK2Allow, v): return PK2ClassAllow
	default: return PK2ClassUnknown
	}
}
