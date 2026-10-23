package main

// samlxmlwrappingdirectoryguard.go —— SAML XML 签名包装特征目录。
//
// 威胁模型：
//   签名置于断言外、xmlns 混淆、外层包装 Response 可让校验与业务读取不一致，
//   必须对同一节点验签并读值。纯字符查表，不用正则。

const (
	SXWClassBlock   = "block"
	SXWClassWarn    = "warn"
	SXWClassAllow   = "allow"
	SXWClassUnknown = "unknown"
)

var SXWBlock = []string{
	"signature-outside",
	"xmlns-confusion",
	"wrapper-response",
	"xsi:type-confusion",
}

var SXWWarn = []string{
	"inclusive-namespaces",
	"xs:id",
}

var SXWAllow = []string{
	"enveloped-signed",
	"same-node",
}

func SXWLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SXWIn(list []string, v string) bool {
	for _, x := range list { if SXWLower(x) == v { return true } }
	return false
}

// SXWClassify 分类单个令牌。
func SXWClassify(tok string) string {
	v := SXWLower(tok)
	switch {
	case SXWIn(SXWBlock, v): return SXWClassBlock
	case SXWIn(SXWWarn, v): return SXWClassWarn
	case SXWIn(SXWAllow, v): return SXWClassAllow
	default: return SXWClassUnknown
	}
}
