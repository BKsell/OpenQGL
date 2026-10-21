package main

// configimportguard.go —— 导入“外部分享配置”时的安全接纳内核。
//
// 与 configwatch / configsnapshot 的区别：
//   configwatch 守护的是“本机文件被外部进程篡改”，configsnapshot 存的是本机
//   可信基线；本模块处理另一条攻击链——用户从论坛/群友/整合包说明里“导入一份
//   别人导出的配置 JSON”。这份数据跨越了信任边界，即便格式完全合法也可能：
//     1. 夹带 UNC / 设备名 / 目录穿越路径，把 javaPath、gameDir 指到网络位置
//        或敏感目录，启动后触发 SMB 凭据泄露或加载恶意 jar；
//     2. 自定义下载/认证/皮肤站基址指向 http 镜像或内网地址（SSRF / 钓鱼），
//        并在 URL 里用 userinfo 做视觉混淆；
//     3. 超大 -Xmx / -Xms 让 JVM 一次性吃光内存；
//     4. extraJvmArgs 里藏 -javaagent / -XX:OnError / -Xverify:none /
//        --add-opens=ALL-UNNAMED 等执行与绕过项；
//     5. JSON 重复键：encoding/json 默认“后者覆盖”，攻击者可用一个看似安全的
//        外层值骗过人工/审计，再用后面的同名键覆盖成恶意值；
//     6. versionId 里塞 ../ 穿越到任意版本目录。
//
// 本模块纯函数：只解析与裁决，不落盘、不改全局状态。

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// ImportConfigLimits 导入配置的量化边界。
type ImportConfigLimits struct {
	MaxBytes      int
	MaxMemoryMB   int
	MinMemoryMB   int
	MaxArgCount   int
	MaxArgBytes   int
	MaxVersionLen int
}

func defaultImportConfigLimits() ImportConfigLimits {
	return ImportConfigLimits{
		MaxBytes:      1 << 20,
		MaxMemoryMB:   32768,
		MinMemoryMB:   256,
		MaxArgCount:   64,
		MaxArgBytes:   4096,
		MaxVersionLen: 64,
	}
}

// ImportedConfig 是跨机器分享配置的最小可接纳字段集。
type ImportedConfig struct {
	JavaPath        string   `json:"javaPath"`
	GameDir         string   `json:"gameDir"`
	VersionID       string   `json:"versionId"`
	MemoryMB        int      `json:"memoryMb"`
	DownloadBaseURL string   `json:"downloadBaseUrl"`
	MetaBaseURL     string   `json:"metaBaseUrl"`
	AuthBaseURL     string   `json:"authBaseUrl"`
	SkinBaseURL     string   `json:"skinBaseUrl"`
	ProxyURL        string   `json:"proxyUrl"`
	ServerHost      string   `json:"serverHost"`
	ServerPort      int      `json:"serverPort"`
	ExtraJVMArgs    []string `json:"extraJvmArgs"`
}

// ImportFinding 单条问题。Severity: reject（必须拒绝导入）/ warn（剥离字段）。
type ImportFinding struct {
	Field    string
	Severity string
	Reason   string
}

const (
	importReject = "reject"
	importWarn   = "warn"
)

// 配置导入语境下不可接受的 JVM 参数危险片段（小写匹配）。
var importDangerousJVMTokens = []string{
	"-javaagent",
	"-agentlib",
	"-agentpath",
	"-xx:onerror",
	"-xx:onoutofmemoryerror",
	"-xx:heapdumppath",
	"-xx:errorfile",
	"-xverify:none",
	"--add-opens=java.base/java.lang=all-unnamed",
	"-djava.security.manager",
	"-djava.rmi.server.hostname",
	"-dcom.sun.management.jmxremote",
	"-djavax.net.ssl.truststore",
	"-dlog4j.configurationfile",
}

// DecodeImportedConfig 严格解析：拒绝重复键、拒绝未知顶层字段、限制大小，
// 然后做语义校验。返回的 findings 中任一 reject 都意味着不得采用该配置。
func DecodeImportedConfig(raw []byte, allowedGameRoots []string, lim ImportConfigLimits) (ImportedConfig, []ImportFinding, error) {
	var cfg ImportedConfig
	if len(raw) == 0 {
		return cfg, nil, errors.New("import-config: 空配置")
	}
	if len(raw) > lim.MaxBytes {
		return cfg, nil, fmt.Errorf("import-config: 配置超过 %d 字节", lim.MaxBytes)
	}
	if err := detectDuplicateJSONKeys(raw); err != nil {
		return cfg, nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, nil, fmt.Errorf("import-config: 解析失败: %w", err)
	}
	if dec.More() {
		return cfg, nil, errors.New("import-config: 存在多段 JSON 文档")
	}

	findings := validateImportedConfig(cfg, allowedGameRoots, lim)
	return cfg, findings, nil
}

// detectDuplicateJSONKeys 检测同一对象内的重复键。encoding/json 默认静默用
// 后者覆盖，这里把它显式化为错误：攻击者可放一个看似安全的外层值骗过人工，
// 再用后面的同名键覆盖成恶意值。
func detectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return checkValue(dec)
}

// checkValue 读取任意一个 JSON 值并在其中所有层级检查重复键。
func checkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil // 标量值，无键命名空间
	}
	switch d {
	case '{':
		return drainObject(dec)
	case '[':
		return drainArray(dec)
	default:
		return nil
	}
}

func skipValue(dec *json.Decoder) error {
	return checkValue(dec)
}

func drainObject(dec *json.Decoder) error {
	seen := map[string]struct{}{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key := keyTok.(string)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("import-config: 重复的配置键 %q", key)
		}
		seen[key] = struct{}{}
		if err := skipValue(dec); err != nil {
			return err
		}
	}
	_, err := dec.Token() // '}'
	return err
}

func drainArray(dec *json.Decoder) error {
	for dec.More() {
		if err := skipValue(dec); err != nil {
			return err
		}
	}
	_, err := dec.Token() // ']'
	return err
}

// validateImportedConfig 对解析后的结构做语义校验。
func validateImportedConfig(cfg ImportedConfig, allowedGameRoots []string, lim ImportConfigLimits) []ImportFinding {
	var f []ImportFinding

	reject := func(field, reason string) {
		f = append(f, ImportFinding{Field: field, Severity: importReject, Reason: reason})
	}

	// —— 路径字段 ——
	if cfg.JavaPath != "" {
		if reason := rejectImportPath(cfg.JavaPath, false, nil); reason != "" {
			reject("javaPath", reason)
		}
	}
	if cfg.GameDir != "" {
		if reason := rejectImportPath(cfg.GameDir, true, allowedGameRoots); reason != "" {
			reject("gameDir", reason)
		}
	}

	// —— versionId：仅允许安全字符集，杜绝目录穿越 ——
	if reason := checkVersionID(cfg.VersionID, lim.MaxVersionLen); reason != "" && cfg.VersionID != "" {
		reject("versionId", reason)
	}

	// —— 内存配额 ——
	if cfg.MemoryMB != 0 {
		if cfg.MemoryMB < lim.MinMemoryMB || cfg.MemoryMB > lim.MaxMemoryMB {
			reject("memoryMb", fmt.Sprintf("内存配额越界 [%d,%d]", lim.MinMemoryMB, lim.MaxMemoryMB))
		}
	}

	// —— URL 字段 ——
	urlFields := map[string]string{
		"downloadBaseUrl": cfg.DownloadBaseURL,
		"metaBaseUrl":     cfg.MetaBaseURL,
		"authBaseUrl":     cfg.AuthBaseURL,
		"skinBaseUrl":     cfg.SkinBaseURL,
		"proxyUrl":        cfg.ProxyURL,
	}
	for field, u := range urlFields {
		if u == "" {
			continue
		}
		// 代理可能是 socks5/http 本地代理，单独放宽到本机回环。
		if field == "proxyUrl" {
			if reason := checkProxyURL(u); reason != "" {
				reject(field, reason)
			}
			continue
		}
		if reason := checkImportHTTPSURL(u); reason != "" {
			reject(field, reason)
		}
	}

	// —— 服务器地址/端口 ——
	if cfg.ServerPort != 0 && (cfg.ServerPort < 1 || cfg.ServerPort > 65535) {
		reject("serverPort", "端口越界")
	}
	if cfg.ServerHost != "" {
		if reason := checkServerHost(cfg.ServerHost); reason != "" {
			reject("serverHost", reason)
		}
	}

	// —— JVM 参数 ——
	if len(cfg.ExtraJVMArgs) > lim.MaxArgCount {
		reject("extraJvmArgs", fmt.Sprintf("参数条数超过上限 %d", lim.MaxArgCount))
	}
	total := 0
	for _, a := range cfg.ExtraJVMArgs {
		total += len(a)
		if reason := checkImportJVMArg(a); reason != "" {
			reject("extraJvmArgs", reason)
		}
	}
	if total > lim.MaxArgBytes {
		reject("extraJvmArgs", "参数总长度超限")
	}

	return f
}

// rejectImportPath 校验导入配置里的路径。requireInsideRoots 时要求 gameDir 位于
// 允许的根目录之内；javaPath 只要求是干净的绝对路径。返回非空 reason 即拒绝。
func rejectImportPath(p string, requireInsideRoots bool, roots []string) string {
	if strings.ContainsAny(p, "\x00\n\r\t") {
		return "路径含控制字符"
	}
	upper := strings.ToUpper(p)
	if strings.HasPrefix(upper, `\\`) || strings.HasPrefix(upper, `//`) {
		return "不允许 UNC/网络路径"
	}
	if containsEnvPlaceholder(p) {
		return "不允许环境变量占位"
	}
	if isDeviceNamePath(p) {
		return "不允许 Windows 设备名"
	}
	if !filepath.IsAbs(p) {
		return "必须为绝对路径"
	}
	clean := filepath.Clean(p)
	if strings.Contains(clean, "..") {
		// Clean 后仍出现 ".." 仅在路径本身异常时；保守拒绝穿越表达。
		if hasParentSegment(p) {
			return "不允许目录穿越"
		}
	}
	if requireInsideRoots {
		inside := false
		for _, r := range roots {
			if r == "" {
				continue
			}
			if pathWithin(clean, filepath.Clean(r)) {
				inside = true
				break
			}
		}
		if len(roots) > 0 && !inside {
			return "游戏目录不在允许的根目录内"
		}
	}
	return ""
}

func hasParentSegment(p string) bool {
	parts := strings.FieldsFunc(filepath.ToSlash(p), func(c rune) bool { return c == '/' })
	for _, seg := range parts {
		if seg == ".." {
			return true
		}
	}
	return false
}

// isDeviceNamePath 检测 Windows 保留设备名（CON/NUL/COM1/AUX 等）作为路径段。
func isDeviceNamePath(p string) bool {
	base := strings.ToUpper(filepath.Base(p))
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	devices := map[string]struct{}{
		"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
		"COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {},
		"LPT1": {}, "LPT2": {}, "LPT3": {},
	}
	_, bad := devices[base]
	return bad
}

func pathWithin(child, root string) bool {
	rel, err := filepath.Rel(root, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func checkVersionID(v string, maxLen int) string {
	if len(v) > maxLen {
		return "版本标识过长"
	}
	if strings.ContainsAny(v, `/\`) || strings.Contains(v, "..") {
		return "版本标识含路径分隔或穿越"
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return "版本标识含非法字符"
		}
	}
	return ""
}

// checkImportHTTPSURL 要求 https、无 userinfo、无显式非标端口、主机不是字面
// 内网/回环地址，且不含片段以外的凭证。
func checkImportHTTPSURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "URL 无法解析"
	}
	if u.Scheme != "https" {
		return "仅允许 https"
	}
	if u.User != nil {
		return "不允许 userinfo"
	}
	host := u.Hostname()
	if host == "" {
		return "缺少主机"
	}
	if ip := net.ParseIP(host); ip != nil && importIPIsInternal(ip) {
		return "不允许指向内网/回环地址"
	}
	port := u.Port()
	if port != "" && port != "443" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "端口非法"
		}
		return "不允许非标端口"
	}
	return ""
}

// checkProxyURL 代理仅允许 http/https/socks5/socks5h，主机必须是回环（本地
// 代理）或域名；禁止指向其他内网主机与 userinfo（防把凭据随配置分享出去）。
func checkProxyURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "代理 URL 无法解析"
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "代理协议不被允许"
	}
	if u.User != nil {
		return "代理地址不得内嵌账号密码"
	}
	host := u.Hostname()
	if host == "" {
		return "代理缺少主机"
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return "代理 IP 仅允许本机回环"
		}
	}
	return ""
}

func checkServerHost(host string) string {
	if strings.ContainsAny(host, " \t\r\n\x00") {
		return "服务器地址含空白/控制字符"
	}
	if strings.Contains(host, "@") {
		return "服务器地址不允许 userinfo"
	}
	return ""
}

func checkImportJVMArg(arg string) string {
	low := strings.ToLower(strings.TrimSpace(arg))
	for _, tok := range importDangerousJVMTokens {
		if low == tok || strings.HasPrefix(low, tok+"=") || strings.HasPrefix(low, tok+" ") {
			return "含危险 JVM 参数: " + tok
		}
	}
	return ""
}

// importIPIsInternal 判断字面 IP 是否为回环/私网/链路本地/多播/未指定地址。
func importIPIsInternal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// HasRejectFindings 便于调用方快速判定是否必须拒绝整份导入。
func HasRejectFindings(findings []ImportFinding) bool {
	for _, x := range findings {
		if x.Severity == importReject {
			return true
		}
	}
	return false
}
