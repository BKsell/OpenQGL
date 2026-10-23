package main

// cachepoisonheaderdirectoryguard.go —— Web 缓存投毒非键头目录。
//
// 威胁模型：
//   X-Forwarded-Host/Scheme/Prefix、X-Original-Url 等默认不参与缓存键却被后端反射，投毒后可污染共享缓存，
//   逗号分隔按请求头精确匹配，纯字符，不用正则。

// CPH 风险类别。
const (
	CPHClassBlock = "block"
	CPHClassWarn  = "warn"
	CPHClassAllow = "allow"
)

const (
	CPHReasonBlock   = "cph-input-hits-blocked-catalog"
	CPHReasonWarn    = "cph-input-hits-review-catalog"
	CPHReasonPrefix  = "cph-input-hits-dangerous-prefix"
	CPHReasonEmpty   = "cph-input-is-empty"
)

var CPHBlock = []string{
	"x-forwarded-host,x-forwarded-scheme,x-forwarded-prefix,x-original-url,x-rewrite-url,x-real-host,x-forwarded-server,http-host,https",
}

var CPHWarn = []string{
	"x-forwarded-for,x-forwarded-proto,x-real-ip,forwarded,via,accept-language,x-forwarded-port,x-forwarded-proto-version,true-client-ip,cf-connecting-ip",
}

var CPHAllow = []string{
	"host,content-length,accept-encoding,content-type,vary,age,cache-control,date,etag,expires",
}

var CPHPrefixLit = []string{
}
var CPHPrefixReason = []string{
}

// CPHFinding 表示一条命中。
type CPHFinding struct {
	Reason string
	Detail string
}

// CPHResult 是审计结果。
type CPHResult struct {
	Safe bool
	Findings []CPHFinding
}

func CPHLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func CPHIn(list []string, v string) bool {
	for _, x := range list { if CPHLower(x) == v { return true } }
	return false
}

func CPHSplit(in string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(in); i++ {
		if i == len(in) || in[i] == ',' { out = append(out, in[start:i]); start = i + 1 }
	}
	return out
}

func CPHKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// CPHHas 判定结果是否含某原因。
func CPHHas(r CPHResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// CPHAudit 审计输入字符串。
func CPHAudit(in string) CPHResult {
	res := CPHResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, CPHFinding{Reason: CPHReasonEmpty}); return res }
	toks := CPHSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := CPHLower(tok)
		key := cmp
		switch {
		case CPHIn(CPHBlock, key):
			res.Findings = append(res.Findings, CPHFinding{Reason: CPHReasonBlock, Detail: key})
		case CPHIn(CPHWarn, key):
			res.Findings = append(res.Findings, CPHFinding{Reason: CPHReasonWarn, Detail: key})
		}
		for i, lit := range CPHPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, CPHFinding{Reason: CPHPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
