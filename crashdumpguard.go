package main

// crashdumpguard.go —— 崩溃转储 / 错误报告落盘与外发前的敏感信息脱敏守卫。
//
// 背景：
//   启动器在 panic、JVM 崩溃（hs_err_pid*.log）、原生崩溃时会产生转储并可能随"问题反馈"
//   上传。转储里高频包含：Authorization 头、Bearer 令牌、session、Cookie、 Mojang / 皮肤站
//   accessToken、刷新令牌、用户名:密码、内网绝对路径（暴露 Windows 用户名）、环境变量里的
//   密钥（_TOKEN/_SECRET/_KEY/APIKEY）。直接落盘或上传等于把凭据外泄。
//
// 本模块做纯字符扫描与替换：
//   1. 识别 key=value / "key":value / 头字段形式的敏感键，值整体打码；
//   2. 识别 Bearer/Basic 认证头方案；
//   3. 识别高熵长十六进制 / JWT 形态（三段 base64url，以 eyJ 开头）；
//   4. 识别 Windows 本地绝对路径里的用户名目录并打码；
//   5. 支持"只检测"（Scan）与"脱敏"（Redact）两种用法。不使用正则。

const (
	CDPReasonSecretKeyValue  = "cdp-secret-key-value"
	CDPReasonBearerToken     = "cdp-bearer-token"
	CDPReasonBasicAuth       = "cdp-basic-auth-header"
	CDPReasonJWTLike         = "cdp-jwt-like-token"
	CDPReasonEnvSecret       = "cdp-env-secret-in-dump"
	CDPReasonHomePathUser    = "cdp-home-path-username-disclosure"
)

// CDPPolicy 控制崩溃转储脱敏严格度。
type CDPPolicy struct {
	RedactKeyValue   bool
	RedactBearer     bool
	RedactBasic      bool
	RedactJWT        bool
	RedactHomePath   bool
	RedactionMark    string // 替换占位
	SecretKeyHints   []string
}

// CDPFinding 记录一处敏感命中。
type CDPFinding struct {
	Reason string
	Offset int
	Detail string
}

// DefaultCDPPolicy 返回默认策略。
func DefaultCDPPolicy() CDPPolicy {
	return CDPPolicy{
		RedactKeyValue: true,
		RedactBearer:   true,
		RedactBasic:    true,
		RedactJWT:      true,
		RedactHomePath: true,
		RedactionMark:  "[REDACTED]",
		SecretKeyHints: []string{
			"password", "passwd", "secret", "token", "access_token", "accesstoken",
			"refresh_token", "client_secret", "apikey", "api_key", "authorization",
			"auth", "cookie", "session", "credential", "private_key",
		},
	}
}

// cdpLowerASCII 归一小写。
func cdpLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// cdpToLower 返回小写副本（按字节，ASCII）。
func cdpToLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = cdpLowerASCII(s[i])
	}
	return string(b)
}

// cdpIsTokenChar 判断是否为键名字符（字母数字 _ -）。
func cdpIsTokenChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '-'
}

// cdpReadKeyAt 从位置 i（指向键名首字符）读取小写键名与其结束位置。
func cdpReadKeyAt(s string, i int) (key string, end int) {
	start := i
	for i < len(s) && cdpIsTokenChar(s[i]) {
		i++
	}
	return cdpToLower(s[start:i]), i
}

// cdpKeyHintHit 判断小写键名是否命中敏感提示（要求是提示词整体，或以下划线结尾包含）。
func cdpKeyHintHit(key string, hints []string) bool {
	for _, h := range hints {
		if key == h {
			return true
		}
	}
	return false
}

// cdpSkipSpaces 跳空白。
func cdpSkipSpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// cdpReadValue 读取一个"值"：引号串或到分隔符为止。
func cdpReadValue(s string, i int) (value string, next int, quoted bool) {
	if i >= len(s) {
		return "", i, false
	}
	if s[i] == '"' || s[i] == '\'' {
		q := s[i]
		j := i + 1
		for j < len(s) && s[j] != q {
			j++
		}
		return s[i+1 : j], j + 1, true
	}
	start := i
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ';' || c == '}' {
			break
		}
		i++
	}
	return s[start:i], i, false
}

// cdpScanKeyValue 在 "key<sep>value" / "key":value 形态中找敏感键值。
func cdpScanKeyValue(s string, pol CDPPolicy) []CDPFinding {
	var out []CDPFinding
	i := 0
	for i < len(s) {
		c := s[i]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isLetter {
			i++
			continue
		}
		keyStart := i
		key, end := cdpReadKeyAt(s, i)
		if !cdpKeyHintHit(key, pol.SecretKeyHints) {
			i = end
			continue
		}
		// 键后允许空白，然后必须是 = : 之一。
		j := cdpSkipSpaces(s, end)
		if j >= len(s) || (s[j] != '=' && s[j] != ':') {
			i = end
			continue
		}
		j = cdpSkipSpaces(s, j+1)
		_, vEnd, _ := cdpReadValue(s, j)
		out = append(out, CDPFinding{Reason: CDPReasonSecretKeyValue, Offset: keyStart, Detail: key})
		i = vEnd
	}
	return out
}

// cdpHasFold 判断 s[i:] 是否以小写 prefix 开头（大小写不敏感）。
func cdpHasFold(s string, i int, prefix string) bool {
	if i+len(prefix) > len(s) {
		return false
	}
	for k := 0; k < len(prefix); k++ {
		if cdpLowerASCII(s[i+k]) != prefix[k] {
			return false
		}
	}
	return true
}

// cdpScanScheme 扫描 Bearer / Basic 认证方案。
func cdpScanScheme(s string, pol CDPPolicy) []CDPFinding {
	var out []CDPFinding
	for i := 0; i < len(s); i++ {
		if pol.RedactBearer && cdpHasFold(s, i, "bearer ") {
			out = append(out, CDPFinding{Reason: CDPReasonBearerToken, Offset: i})
		}
		if pol.RedactBasic && cdpHasFold(s, i, "basic ") {
			out = append(out, CDPFinding{Reason: CDPReasonBasicAuth, Offset: i})
		}
	}
	return out
}

// cdpIsBase64URLChar 判断 JWT 字符集。
func cdpIsBase64URLChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
}

// cdpScanJWT 扫描 eyJ 开头、含两个点、足够长的 JWT 形态。
func cdpScanJWT(s string, pol CDPPolicy) []CDPFinding {
	var out []CDPFinding
	if !pol.RedactJWT {
		return out
	}
	for i := 0; i+3 <= len(s); i++ {
		if !cdpHasFold(s, i, "eyj") {
			continue
		}
		j := i
		dots := 0
		for j < len(s) && cdpIsBase64URLChar(s[j]) {
			if s[j] == '.' {
				dots++
			}
			j++
		}
		if dots >= 2 && j-i >= 20 {
			out = append(out, CDPFinding{Reason: CDPReasonJWTLike, Offset: i, Detail: "jwt"})
			i = j
		}
	}
	return out
}

// cdpScanHomePath 扫描 C:\Users\<name>\ 形式的本地路径，标记用户名泄露位置。
func cdpScanHomePath(s string, pol CDPPolicy) []CDPFinding {
	var out []CDPFinding
	if !pol.RedactHomePath {
		return out
	}
	i := 0
	for i < len(s) {
		hit := cdpHasFold(s, i, `\users\`) || cdpHasFold(s, i, "/users/")
		if !hit {
			i++
			continue
		}
		segStart := i + len(`\users\`)
		k := segStart
		for k < len(s) && s[k] != '\\' && s[k] != '/' {
			k++
		}
		if k > segStart {
			out = append(out, CDPFinding{Reason: CDPReasonHomePathUser, Offset: segStart, Detail: s[segStart:k]})
		}
		i = k
	}
	return out
}

// CDPScan 汇总检测崩溃文本中的敏感信息（不去重也可，调用方按 Offset 处理）。
func CDPScan(text string, pol CDPPolicy) []CDPFinding {
	var out []CDPFinding
	out = append(out, cdpScanKeyValue(text, pol)...)
	out = append(out, cdpScanScheme(text, pol)...)
	out = append(out, cdpScanJWT(text, pol)...)
	out = append(out, cdpScanHomePath(text, pol)...)
	return out
}

// CDPRedact 返回把敏感值打码后的安全文本。采用保守策略：对键值 / 认证方案 / JWT 用占位替换，
// 对主目录用户名段替换为占位。
func CDPRedact(text string, pol CDPPolicy) string {
	mark := pol.RedactionMark
	if mark == "" {
		mark = "[REDACTED]"
	}
	out := []byte(text)

	// 主目录用户名：把 Users\<name>\ 的 name 段替换成占位。
	out = cdpRedactHomePath(out, mark)
	// JWT。
	out = cdpRedactJWT(out, mark)
	// Bearer / Basic。
	out = cdpRedactScheme(out, "bearer ", mark)
	out = cdpRedactScheme(out, "basic ", mark)
	// 键值。
	out = cdpRedactKV(out, pol, mark)
	return string(out)
}

// cdpRedactHomePath 替换主目录中的用户名段。
func cdpRedactHomePath(b []byte, mark string) []byte {
	s := string(b)
	res := ""
	i := 0
	for i < len(s) {
		hit := cdpHasFold(s, i, `\users\`) || cdpHasFold(s, i, "/users/")
		if !hit {
			res += string(s[i])
			i++
			continue
		}
		res += s[i : i+len(`\users\`)]
		res += mark
		k := i + len(`\users\`)
		for k < len(s) && s[k] != '\\' && s[k] != '/' {
			k++
		}
		i = k
	}
	return []byte(res)
}

// cdpRedactJWT 替换 JWT 形态串。
func cdpRedactJWT(b []byte, mark string) []byte {
	s := string(b)
	res := ""
	i := 0
	for i < len(s) {
		if cdpHasFold(s, i, "eyj") {
			j := i
			dots := 0
			for j < len(s) && cdpIsBase64URLChar(s[j]) {
				if s[j] == '.' {
					dots++
				}
				j++
			}
			if dots >= 2 && j-i >= 20 {
				res += mark
				i = j
				continue
			}
		}
		res += string(s[i])
		i++
	}
	return []byte(res)
}

// cdpRedactScheme 替换 "scheme <credential>" 的凭证部分（到空白/行尾）。
func cdpRedactScheme(b []byte, schemeLower string, mark string) []byte {
	s := string(b)
	res := ""
	i := 0
	for i < len(s) {
		if cdpHasFold(s, i, schemeLower) {
			res += s[i : i+len(schemeLower)]
			j := i + len(schemeLower)
			for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '\r' && s[j] != '\n' {
				j++
			}
			res += mark
			i = j
			continue
		}
		res += string(s[i])
		i++
	}
	return []byte(res)
}

// cdpRedactKV 替换敏感键的值。
func cdpRedactKV(b []byte, pol CDPPolicy, mark string) []byte {
	s := string(b)
	res := ""
	i := 0
	for i < len(s) {
		c := s[i]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isLetter {
			res += string(c)
			i++
			continue
		}
		keyStart := i
		key, end := cdpReadKeyAt(s, i)
		if !cdpKeyHintHit(key, pol.SecretKeyHints) {
			res += s[i:end]
			i = end
			continue
		}
		j := cdpSkipSpaces(s, end)
		if j >= len(s) || (s[j] != '=' && s[j] != ':') {
			res += s[i:end]
			i = end
			continue
		}
		sep := s[j]
		after := cdpSkipSpaces(s, j+1)
		_, vEnd, _ := cdpReadValue(s, after)
		res += s[keyStart:end]
		// 保留原空白与分隔符。
		res += s[end:j+1]
		res += s[j+1:after]
		res += mark
		i = vEnd
		_ = sep
	}
	return []byte(res)
}

// CDPIsSafe 便捷判定：转储文本是否不含已知敏感形态。
func CDPIsSafe(text string) bool {
	return len(CDPScan(text, DefaultCDPPolicy())) == 0
}
