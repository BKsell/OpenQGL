package main

// httpheadercatalogguard.go —— HTTP 头字段风险目录（逐跳/路由伪造/敏感）。
//
// 威胁模型：
//   出向请求由多组件拼接头。逐跳头被转发会造成请求走私/缓存投毒；Host/Forwarded 类头可被远端清单注入
//   导致 SSRF 或鉴权绕过；凭据头不得落日志。本模块按逗号分隔头集合做纯判定，不用正则。

// HHC 风险类别。
const (
	HHCClassBlock = "block"
	HHCClassWarn  = "warn"
	HHCClassAllow = "allow"
)

const (
	HHCReasonBlock   = "hhc-input-hits-blocked-catalog"
	HHCReasonWarn    = "hhc-input-hits-review-catalog"
	HHCReasonPrefix  = "hhc-input-hits-dangerous-prefix"
	HHCReasonEmpty   = "hhc-input-is-empty"
)

var HHCBlock = []string{
	"connection",
	"keep-alive",
	"proxy-connection",
	"transfer-encoding",
	"te",
	"trailer",
	"upgrade",
	"x-forwarded-host",
	"x-forwarded-server",
	"x-original-url",
	"x-rewrite-url",
	"x-http-method-override",
	"x-forwarded-method",
	"proxy-authorization",
	"www-authenticate",
	"content-length",
	"host",
}

var HHCWarn = []string{
	"x-forwarded-for",
	"forwarded",
	"x-real-ip",
	"x-client-ip",
	"x-forwarded-proto",
	"x-forwarded-scheme",
	"referer",
	"origin",
	"cookie",
	"set-cookie",
	"authorization",
	"x-api-key",
	"x-auth-token",
	"x-csrf-token",
}

var HHCAllow = []string{
	"accept",
	"accept-language",
	"accept-encoding",
	"user-agent",
	"content-type",
	"if-none-match",
	"if-modified-since",
	"cache-control",
	"pragma",
	"date",
	"x-request-id",
	"vary",
	"accept-charset",
}

var HHCPrefixLit = []string{
	"proxy-",
	"x-forwarded-",
}
var HHCPrefixReason = []string{
	"proxy-routing-header-injection",
	"forwarding-chain-header-spoofing",
}

// HHCFinding 表示一条命中。
type HHCFinding struct {
	Reason string
	Detail string
}

// HHCResult 是审计结果。
type HHCResult struct {
	Safe bool
	Findings []HHCFinding
}

func HHCLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func HHCIn(list []string, v string) bool {
	for _, x := range list { if HHCLower(x) == v { return true } }
	return false
}

func HHCSplit(in string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(in); i++ {
		if i == len(in) || in[i] == ',' { out = append(out, in[start:i]); start = i + 1 }
	}
	return out
}

func HHCKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// HHCHas 判定结果是否含某原因。
func HHCHas(r HHCResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// HHCAudit 审计输入字符串。
func HHCAudit(in string) HHCResult {
	res := HHCResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, HHCFinding{Reason: HHCReasonEmpty}); return res }
	toks := HHCSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := HHCLower(tok)
		key := cmp
		switch {
		case HHCIn(HHCBlock, key):
			res.Findings = append(res.Findings, HHCFinding{Reason: HHCReasonBlock, Detail: key})
		case HHCIn(HHCWarn, key):
			res.Findings = append(res.Findings, HHCFinding{Reason: HHCReasonWarn, Detail: key})
		}
		for i, lit := range HHCPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, HHCFinding{Reason: HHCPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
