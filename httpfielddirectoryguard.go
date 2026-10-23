package main

// httpfielddirectoryguard.go —— HTTP 头字段登记与风险目录。
//
// 威胁模型：
//   多组件拼接头时需识别逐跳/路由伪造/敏感头（阻断）、凭据与寻址头（复核）、安全常规头（放行），
//   未登记头用于发现走私/缓存投毒注入。纯字符查表，不用正则。

// HFD 风险类别。
const (
	HFDClassBlock = "block"
	HFDClassWarn  = "warn"
	HFDClassAllow = "allow"
)

const (
	HFDReasonBlock   = "hfd-input-hits-blocked-catalog"
	HFDReasonWarn    = "hfd-input-hits-review-catalog"
	HFDReasonPrefix  = "hfd-input-hits-dangerous-prefix"
	HFDReasonEmpty   = "hfd-input-is-empty"
)

var HFDBlock = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Transfer-Encoding",
	"TE",
	"Trailer",
	"Upgrade",
	"Proxy-Authorization",
	"X-Forwarded-Host",
	"X-Forwarded-For",
	"X-Forwarded-Proto",
	"X-Forwarded-Scheme",
	"X-Real-Ip",
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
	"Forwarded",
	"Via",
	"X-Host",
	"X-Forwarded-Server",
	"X-Forwarded-Port",
	"X-Envoy-Original-Auth",
	"X-Envoy-External-Address",
}

var HFDWarn = []string{
	"Host",
	"Authorization",
	"Cookie",
	"Set-Cookie",
	"Cookie2",
	"X-Api-Key",
	"X-Auth-Token",
	"X-Access-Token",
	"X-Csrf-Token",
	"X-Xsrf-Token",
	"X-Session-Id",
	"X-Session-Token",
	"X-Request-Id",
	"X-Correlation-Id",
	"X-Trace-Id",
	"Proxy-Authenticate",
	"WWW-Authenticate",
	"X-User-Id",
	"X-Identity",
	"X-Email",
	"X-Username",
	"X-Forwarded-User",
	"X-Remote-User",
	"X-Remote-Addr",
	"X-Client-Ip",
	"X-Client-Cert",
	"X-SSL-Client-Cert",
	"X-Webauth-User",
	"X-Original-Host",
	"Content-Length",
	"Content-Range",
	"Range",
	"If-Range",
	"Referer",
	"Origin",
	"Location",
	"Destination",
	"From",
	"Expect",
	"X-Custom-IP-Authorization",
	"X-Cluster-Client-Ip",
	"True-Client-Ip",
	"CF-Connecting-IP",
	"Fastly-Client-Ip",
	"X-Amzn-Trace-Id",
	"CloudFront-Viewer-Address",
}

var HFDAllow = []string{
	"Accept",
	"Accept-Charset",
	"Accept-Encoding",
	"Accept-Language",
	"Accept-Datetime",
	"Accept-Patch",
	"Accept-Post",
	"Accept-Ranges",
	"Content-Type",
	"Content-Language",
	"Content-Encoding",
	"Content-Location",
	"Content-Disposition",
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Embedder-Policy",
	"Cross-Origin-Resource-Policy",
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Referrer-Policy",
	"Permissions-Policy",
	"X-Permitted-Cross-Domain-Policies",
	"Cache-Control",
	"Pragma",
	"Expires",
	"Age",
	"Date",
	"ETag",
	"Last-Modified",
	"Vary",
	"Warning",
	"Allow",
	"Server-Timing",
	"Timing-Allow-Origin",
	"X-Request-Timeout",
	"X-Server",
	"Link",
	"Retry-After",
	"Alt-Svc",
	"Early-Data",
	"DNT",
	"Sec-Ch-Ua",
	"Sec-Ch-Ua-Mobile",
	"Sec-Ch-Ua-Platform",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-User",
	"Sec-Fetch-Dest",
	"Sec-Gpc",
	"Save-Data",
	"Device-Memory",
	"Downlink",
	"Ect",
	"Rtt",
	"Viewport-Width",
	"Width",
	"Priority",
	"Service-Worker-Navigation-Preload",
}

var HFDPrefixLit = []string{
}
var HFDPrefixReason = []string{
}

// HFDFinding 表示一条命中。
type HFDFinding struct {
	Reason string
	Detail string
}

// HFDResult 是审计结果。
type HFDResult struct {
	Safe bool
	Findings []HFDFinding
}

func HFDLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func HFDIn(list []string, v string) bool {
	for _, x := range list { if HFDLower(x) == v { return true } }
	return false
}

func HFDSplit(in string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(in); i++ {
		if i == len(in) || in[i] == ',' { out = append(out, in[start:i]); start = i + 1 }
	}
	return out
}

func HFDKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// HFDHas 判定结果是否含某原因。
func HFDHas(r HFDResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// HFDAudit 审计输入字符串。
func HFDAudit(in string) HFDResult {
	res := HFDResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, HFDFinding{Reason: HFDReasonEmpty}); return res }
	toks := HFDSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := HFDLower(tok)
		key := cmp
		switch {
		case HFDIn(HFDBlock, key):
			res.Findings = append(res.Findings, HFDFinding{Reason: HFDReasonBlock, Detail: key})
		case HFDIn(HFDWarn, key):
			res.Findings = append(res.Findings, HFDFinding{Reason: HFDReasonWarn, Detail: key})
		}
		for i, lit := range HFDPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, HFDFinding{Reason: HFDPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
