package main

// secrettagcatalogguard.go —— 配置键名密钥识别目录。
//
// 威胁模型：
//   配置/JSON/YAML/properties 中疑似密钥的键名若明文落盘或上报遥测即构成泄露。本模块按键名目录与命名片段
//   识别敏感键，纯字符判定，值不参与，不用正则。

// STC 风险类别。
const (
	STCClassBlock = "block"
	STCClassWarn  = "warn"
	STCClassAllow = "allow"
)

const (
	STCReasonBlock   = "stc-input-hits-blocked-catalog"
	STCReasonWarn    = "stc-input-hits-review-catalog"
	STCReasonPrefix  = "stc-input-hits-dangerous-prefix"
	STCReasonEmpty   = "stc-input-is-empty"
)

var STCBlock = []string{
	"password",
	"passwd",
	"pwd",
	"secret",
	"client_secret",
	"clientsecret",
	"token",
	"access_token",
	"refresh_token",
	"id_token",
	"api_key",
	"apikey",
	"api-key",
	"authorization",
	"auth_token",
	"authtoken",
	"private_key",
	"privatekey",
	"private-key",
	"session_key",
	"encryption_key",
	"signing_key",
	"aws_secret_access_key",
	"secret_access_key",
	"license_key",
	"webhook_secret",
	"oauth_token",
	"bearer_token",
	"credential",
	"credentials",
	"keystore_password",
	"truststore_password",
	"db_password",
	"database_password",
	"mojang_access_token",
	"xbox_token",
	"xsts_token",
	"client_secret_key",
}

var STCWarn = []string{
	"email",
	"phone",
	"username",
	"user_id",
	"uuid",
	"mc_uuid",
	"display_name",
	"ip",
	"last_ip",
	"session_id",
	"device_id",
	"client_id",
	"redirect_uri",
	"code_verifier",
	"code_challenge",
}

var STCAllow = []string{
	"name",
	"version",
	"os",
	"arch",
	"ram",
	"java_path",
	"java_version",
	"memory",
	"resolution",
	"width",
	"height",
	"fullscreen",
	"game_directory",
	"assets",
	"version_type",
}

var STCPrefixLit = []string{
	"token",
	"secret",
	"password",
	"credential",
	"auth",
}
var STCPrefixReason = []string{
	"key-name-contains-token",
	"key-name-contains-secret",
	"key-name-contains-password",
	"key-name-contains-credential",
	"key-name-contains-auth",
}

// STCFinding 表示一条命中。
type STCFinding struct {
	Reason string
	Detail string
}

// STCResult 是审计结果。
type STCResult struct {
	Safe bool
	Findings []STCFinding
}

func STCLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func STCIn(list []string, v string) bool {
	for _, x := range list { if STCLower(x) == v { return true } }
	return false
}

func STCSplit(in string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(in); i++ {
		end := i == len(in)
		sep := false
		if !end { c := in[i]; sep = c == ' ' || c == '\t' || c == '\n' || c == '\r' }
		if end || sep {
			if start >= 0 { out = append(out, in[start:i]); start = -1 }
		} else if start < 0 {
			start = i
		}
	}
	return out
}

func STCKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// STCHas 判定结果是否含某原因。
func STCHas(r STCResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// STCAudit 审计输入字符串。
func STCAudit(in string) STCResult {
	res := STCResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, STCFinding{Reason: STCReasonEmpty}); return res }
	toks := STCSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := STCLower(tok)
		key := cmp
		switch {
		case STCIn(STCBlock, key):
			res.Findings = append(res.Findings, STCFinding{Reason: STCReasonBlock, Detail: key})
		case STCIn(STCWarn, key):
			res.Findings = append(res.Findings, STCFinding{Reason: STCReasonWarn, Detail: key})
		}
		for i, lit := range STCPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, STCFinding{Reason: STCPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
