package main

// envsecretcatalogguard.go —— 环境变量敏感凭据名目录。
//
// 威胁模型：
//   进程环境里出现密钥/口令/private_key/client_secret 等变量名即判定敏感，落盘日志与错误回显必须脱敏，
//   普通非密变量放行。纯字符查表，不用正则。

const (
	ESCClassBlock   = "block"
	ESCClassWarn    = "warn"
	ESCClassAllow   = "allow"
	ESCClassUnknown = "unknown"
)

var ESCBlock = []string{
	"aws_secret_access_key",
	"aws_session_token",
	"github_token",
	"private_key",
	"client_secret",
	"password",
	"passwd",
	"db_password",
	"database_password",
	"encryption_key",
	"secret_key",
	"access_token",
	"refresh_token",
	"id_rsa",
	"ssh_passphrase",
	"npm_token",
	"pypi_token",
	"docker_password",
	"keystore_password",
	"truststore_password",
	"jwt_secret",
	"slack_token",
	"discord_token",
	"telegram_bot_token",
}

var ESCWarn = []string{
	"aws_access_key_id",
	"api_key",
	"apikey",
	"token",
	"secret",
	"credential",
	"credentials",
	"database_url",
	"connection_string",
	"bearer",
	"authorization",
	"otp",
	"mfa_code",
	"registry_password",
	"vault_token",
	"gpg_passphrase",
}

var ESCAllow = []string{
	"path",
	"home",
	"user",
	"lang",
	"tmpdir",
	"hostname",
	"editor",
	"shell",
	"term",
	"port",
	"host",
}

func ESCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func ESCIn(list []string, v string) bool {
	for _, x := range list { if ESCLower(x) == v { return true } }
	return false
}

// ESCClassify 分类单个令牌。
func ESCClassify(tok string) string {
	v := ESCLower(tok)
	switch {
	case ESCIn(ESCBlock, v): return ESCClassBlock
	case ESCIn(ESCWarn, v): return ESCClassWarn
	case ESCIn(ESCAllow, v): return ESCClassAllow
	default: return ESCClassUnknown
	}
}
