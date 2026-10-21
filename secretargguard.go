package main

// secretargguard.go —— 子进程命令行（argv）中的敏感凭据泄露守卫。
//
// 威胁模型：
//   启动器最终以子进程方式启动 Java（游戏）以及可能的辅助进程。命令行参数在
//   多数系统上对同机其他进程可读：
//     - Windows：NtQuerySystemInformation / Process Explorer 可读其他进程命令行；
//     - Linux：/proc/<pid>/cmdline 通常对本人（有时更宽）可读；
//     - macOS：ps 对本人进程可见。
//   把 Minecraft accessToken、Yggdrasil session、密码、--accessToken、Bearer
//   令牌放进 argv，会让同机任何低权限程序、录屏/诊断工具、崩溃收集器、甚至
//   hs_err 与日志里回显的完整命令行直接拿到凭据。
//
//   正确做法是把这类秘密放进子进程 stdin（管道）或受限权限的临时应答文件，
//   argv 里只允许出现占位/句柄。本模块在“组装完最终 argv 之后、真正 exec
//   之前”做最后一道静态审计：
//     1. 按已知危险参数名（--accessToken / --username 配 --password /
//        -Dauth.token / Authorization 等）识别；
//     2. 按令牌形态识别（Mojang 新版 JWT 三段式、长十六进制、Base64URL、
//        Bearer 前缀），即使参数名是良性的也拦；
//     3. 给出每条命中的索引与原因，调用方据此改为 stdin/受控通道；
//     4. 提供 PlaceholderForSecret 生成不可逆占位，供需要打印命令行的场景。
//
// 纯函数，不启动进程、不读环境、不做网络。

import (
	"errors"
	"strings"
)

// SecretArgFinding 单条敏感参数命中。
type SecretArgFinding struct {
	Index    int
	Arg      string
	Reason   string
	Category string
}

// 秘密参数类别。
const (
	secretCategoryToken    = "access-token"
	secretCategoryPassword = "password"
	secretCategorySession  = "session"
	secretCategoryJWT      = "jwt"
	secretCategoryHex      = "hex-secret"
	secretCategoryBearer   = "bearer"
	secretCategoryCredProp = "credential-property"
)

// errSecretArgPresent 表示 argv 中存在必须改走安全通道的敏感参数。
var errSecretArgPresent = errors.New("secret-arg: 命令行中存在敏感凭据，必须改走 stdin 或受控应答文件")

// 已知会直接携带秘密的参数名（小写比较，覆盖 --name value 与 --name=value）。
var secretArgNames = map[string]string{
	"--accesstoken":          secretCategoryToken,
	"--access_token":         secretCategoryToken,
	"--token":                secretCategoryToken,
	"--session":              secretCategorySession,
	"--sessionid":            secretCategorySession,
	"--uuid":                 secretCategoryToken, // 与 token 同行下发，保守视为敏感
	"--password":             secretCategoryPassword,
	"--pass":                 secretCategoryPassword,
	"--usertype":             "", // 本身不敏感，跳过（仅记录相邻上下文需要时用）
}

// -D 形式的凭据系统属性。
var secretPropNames = map[string]string{
	"auth.token":               secretCategoryToken,
	"accesstoken":              secretCategoryToken,
	"minecraft.api.accesstoken": secretCategoryToken,
	"password":                 secretCategoryPassword,
	"javax.net.ssl.keystorepassword": secretCategoryPassword,
	"javax.net.ssl.truststorepassword": secretCategoryPassword,
	"http.proxypassword":       secretCategoryPassword,
	"https.proxypassword":      secretCategoryPassword,
	"login.password":           secretCategoryPassword,
}

// AuditSecretArgs 审计完整 argv。返回的 findings 非空即表示不得直接 exec；
// allowInArgValue 的键为调用方明确允许出现在命令行里的值（例如占位符句柄），
// 命中这些值不报。
func AuditSecretArgs(argv []string, allowInArgValue map[string]struct{}) []SecretArgFinding {
	var findings []SecretArgFinding
	for i, arg := range argv {
		if arg == "" {
			continue
		}
		if _, allow := allowInArgValue[arg]; allow {
			continue
		}
		if f := classifyArg(i, arg); f != nil {
			findings = append(findings, *f)
			continue
		}
		// --name value 形式：当前参数是危险开关且后面确实跟了一个值，记在值上。
		if cat := leadingSecretSwitch(arg); cat != "" {
			if i+1 < len(argv) && argv[i+1] != "" {
				if _, allow := allowInArgValue[argv[i+1]]; !allow && !looksLikeFlag(argv[i+1]) {
					findings = append(findings, SecretArgFinding{
						Index: i + 1, Arg: argv[i+1], Reason: "紧跟敏感开关的秘密值", Category: cat,
					})
				}
			}
		}
	}
	return findings
}

// classifyArg 判定单个参数自身是否携带秘密。
func classifyArg(i int, arg string) *SecretArgFinding {
	low := strings.ToLower(strings.TrimSpace(arg))

	// 1) --name=value 形式。
	if strings.HasPrefix(low, "--") {
		if eq := strings.IndexByte(low, '='); eq >= 0 {
			name := low[2:eq]
			if cat, ok := secretArgNames[name]; ok && cat != "" {
				val := arg[eq+1:]
				if val != "" {
					return &SecretArgFinding{Index: i, Arg: arg, Reason: "敏感命令行开关内联秘密", Category: cat}
				}
			}
		}
	}

	// 2) -Dprop=value 形式。
	if strings.HasPrefix(low, "-d") {
		body := arg[2:]
		if eq := strings.IndexByte(body, '='); eq >= 0 {
			prop := strings.ToLower(body[:eq])
			if cat, ok := secretPropNames[prop]; ok {
				if body[eq+1:] != "" {
					return &SecretArgFinding{Index: i, Arg: arg, Reason: "JVM 系统属性携带凭据", Category: cat}
				}
			}
		}
	}

	// 3) Authorization: Bearer 形态（个别辅助工具会走命令行）。
	if idx := strings.Index(low, "bearer "); idx >= 0 {
		token := strings.TrimSpace(arg[idx+len("bearer "):])
		if looksLikeSecretToken(token) {
			return &SecretArgFinding{Index: i, Arg: arg, Reason: "Bearer 凭据出现在命令行", Category: secretCategoryBearer}
		}
	}

	// 4) 纯令牌形态：JWT 三段式 / 长十六进制 / 长 Base64URL。
	//    只在“整串就是令牌”时判定，避免误伤普通短参数与文件路径。
	if looksLikeSecretToken(arg) {
		cat := secretCategoryHex
		if isJWTShape(arg) {
			cat = secretCategoryJWT
		}
		return &SecretArgFinding{Index: i, Arg: arg, Reason: "命令行参数呈高熵令牌形态", Category: cat}
	}
	return nil
}

// leadingSecretSwitch 处理不带 '=' 的危险开关本身（--accessToken），返回其类别。
func leadingSecretSwitch(arg string) string {
	low := strings.ToLower(strings.TrimSpace(arg))
	if !strings.HasPrefix(low, "--") {
		return ""
	}
	name := low[2:]
	if strings.IndexByte(name, '=') >= 0 {
		return "" // 内联形式已在 classifyArg 处理
	}
	if cat, ok := secretArgNames[name]; ok {
		return cat
	}
	return ""
}

func looksLikeFlag(s string) bool {
	return strings.HasPrefix(s, "-") && len(s) >= 2
}

// looksLikeSecretToken 识别“整串就是秘密”的高熵形态：
//   - JWT：三段以 '.' 连接，每段 Base64URL，至少两非空段；
//   - 长十六进制：>=32 个 [0-9a-fA-F]（典型 accessToken/session 十六进制）；
//   - 长 Base64URL：>=40 且字符集为 URL-safe base64。
// 不使用正则，逐字符判断。
func looksLikeSecretToken(s string) bool {
	if isJWTShape(s) {
		return true
	}
	if isLongHex(s, 32) {
		return true
	}
	if isLongBase64URL(s, 40) {
		return true
	}
	return false
}

func isJWTShape(s string) bool {
	parts := splitByte(s, '.')
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) < 4 || !isBase64URLAlphabet(p) {
			return false
		}
	}
	// 第一段 header 解码后通常含 "alg"，这里只做形态约束，不实际解码（避免引入
	// 对合法但非 JWT 的三段点串误报：三段都满足长度与字母表已足够强）。
	return true
}

func isLongHex(s string, minLen int) bool {
	if len(s) < minLen {
		return false
	}
	// 纯十六进制串通常只含 0-9a-f，若含字母则要求不是普通英文单词——长度阈值
	// 32 已天然排除自然语言。
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isLongBase64URL(s string, minLen int) bool {
	if len(s) < minLen {
		return false
	}
	// 排除明显路径/文件名：含路径分隔或空格则不当令牌。
	if strings.ContainsAny(s, `/\ `) {
		return false
	}
	return isBase64URLAlphabet(s)
}

func isBase64URLAlphabet(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		// 末尾允许 '=' 填充。
		if !ok && !(c == '=' && i >= len(s)-2) {
			return false
		}
	}
	return true
}

func splitByte(s string, b byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// SecretArgsSafe 便于调用方在 exec 前做布尔判定。
func SecretArgsSafe(argv []string, allow map[string]struct{}) (bool, []SecretArgFinding) {
	f := AuditSecretArgs(argv, allow)
	return len(f) == 0, f
}

// SecretArgError 在有命中时返回统一错误，供调用方拒绝启动。
func SecretArgError(findings []SecretArgFinding) error {
	if len(findings) == 0 {
		return nil
	}
	return errSecretArgPresent
}

// PlaceholderForSecret 生成可安全放进命令行/日志的不可逆占位符。
// kind 标识用途，id 为调用方侧的句柄编号；不含任何秘密材料。
func PlaceholderForSecret(kind string, id int) string {
	return "@secret:" + kind + ":" + itoaSafe(id)
}

// RedactArgvForLog 返回一份用于日志/崩溃回显的 argv：命中位置整体替换为
// '[REDACTED]'，绝不保留秘密片段。
func RedactArgvForLog(argv []string) []string {
	out := make([]string, len(argv))
	copy(out, argv)
	findings := AuditSecretArgs(argv, nil)
	hit := map[int]struct{}{}
	for _, f := range findings {
		hit[f.Index] = struct{}{}
	}
	for i := range out {
		if _, bad := hit[i]; bad {
			out[i] = "[REDACTED]"
		}
	}
	return out
}
