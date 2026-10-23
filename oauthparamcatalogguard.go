package main

// oauthparamcatalogguard.go —— OAuth/OIDC 参数风险目录。
//
// 威胁模型：
//   授权请求/回调参数中 response_type=token（隐式）、宽松 prompt、关闭校验的参数需复核，标准 state/nonce/scope
//   等常规。纯字符查表，不用正则。

// OPM 风险类别。
const (
	OPMClassBlock = "block"
	OPMClassWarn  = "warn"
	OPMClassAllow = "allow"
)

const (
	OPMReasonBlock   = "opm-input-hits-blocked-catalog"
	OPMReasonWarn    = "opm-input-hits-review-catalog"
	OPMReasonPrefix  = "opm-input-hits-dangerous-prefix"
	OPMReasonEmpty   = "opm-input-is-empty"
)

var OPMBlock = []string{
	"response_type=token",
	"response_type=code token",
	"response_type=token id_token",
	"grant_type=implicit",
	"implicit",
	"prompt=none",
	"prompt=consent-bypass",
	"approval_prompt=auto",
	"trust=yes",
	"skipconsent",
	"novalidate",
	"disable_pkce",
	"code_challenge_method=plain",
	"response_mode=fragment",
	"redirect_uri=javascript",
	"redirect_uri=data",
	"redirect_uri=file",
}

var OPMWarn = []string{
	"response_type",
	"response_mode",
	"prompt",
	"approval_prompt",
	"display",
	"login_hint",
	"domain_hint",
	"access_type",
	"code_challenge",
	"code_challenge_method",
	"code_verifier",
	"nonce",
	"state",
	"scope",
	"resource",
	"audience",
	"client_secret",
	"client_assertion",
	"client_assertion_type",
	"grant_type",
	"refresh_token",
	"device_code",
	"token_endpoint_auth_method",
	"response_type=code",
	"code_challenge_method=S256",
	"prompt=login",
	"prompt=consent",
	"prompt=select_account",
	"access_type=offline",
}

var OPMAllow = []string{
	"client_id",
	"redirect_uri",
	"code",
	"authorization_code",
	"client_credentials",
	"S256",
	"openid",
	"profile",
	"email",
	"offline_access",
	"iss",
	"aud",
	"exp",
	"iat",
	"sub",
	"jti",
	"kid",
	"typ",
	"alg",
	"azp",
	"at_hash",
	"c_hash",
}

var OPMPrefixLit = []string{
}
var OPMPrefixReason = []string{
}

// OPMFinding 表示一条命中。
type OPMFinding struct {
	Reason string
	Detail string
}

// OPMResult 是审计结果。
type OPMResult struct {
	Safe bool
	Findings []OPMFinding
}

func OPMLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func OPMIn(list []string, v string) bool {
	for _, x := range list { if OPMLower(x) == v { return true } }
	return false
}

func OPMSplit(in string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(in); i++ {
		if i == len(in) || in[i] == ',' { out = append(out, in[start:i]); start = i + 1 }
	}
	return out
}

func OPMKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// OPMHas 判定结果是否含某原因。
func OPMHas(r OPMResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// OPMAudit 审计输入字符串。
func OPMAudit(in string) OPMResult {
	res := OPMResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, OPMFinding{Reason: OPMReasonEmpty}); return res }
	toks := OPMSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := OPMLower(tok)
		key := cmp
		switch {
		case OPMIn(OPMBlock, key):
			res.Findings = append(res.Findings, OPMFinding{Reason: OPMReasonBlock, Detail: key})
		case OPMIn(OPMWarn, key):
			res.Findings = append(res.Findings, OPMFinding{Reason: OPMReasonWarn, Detail: key})
		}
		for i, lit := range OPMPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, OPMFinding{Reason: OPMPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
