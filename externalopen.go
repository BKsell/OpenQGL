package main

import (
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
)

// externalopen.go —— “把一个 URL 交给系统浏览器打开”的安全内核。
//
// 威胁模型：
//   启动器里有若干处需要替用户打开网页（典型：需要用户手动下载某大版本 JRE 时，
//   downloadJavaItem 用 rundll32 url.dll,FileProtocolHandler <url> 打开厂商下载页）。
//   历史上这里只校验了字符串前缀是不是 "https"。仅查前缀挡不住这些情况：
//     1) 危险 scheme： url 以 https 开头但实际是 "https://x\r\nfile:///..."、或带
//        制表/换行，交给 ShellExecute 一族时可能被截断、按后半段解释；
//     2) userinfo 视觉混淆： https://www.oracle.com@evil.test/，用户看到的是 oracle；
//     3) 指向内网 / 本机： https://127.0.0.1:xxxx/、https://169.254.169.254/（云元数据）
//        等，浏览器会带着本机网络身份去访问，形成 SSRF / 打本机服务的跳板；
//     4) 非标准端口 / 畸形 host。
//
//   本模块只做两件纯逻辑事：ValidateBrowserURL 判定一个 URL 是否“适合交给浏览器”，
//   BrowserOpenCommand 据平台构造 *exec.Cmd（但不启动）。真正启动由调用方完成，
//   便于在单测里不实际拉起浏览器。
//
//   注意：这里的场景是“打开厂商下载页”，host 不固定（Adoptium / Corretto / Azul /
//   Oracle 等都可能），所以不采用 url_policy.go 那种固定白名单，而是采用“https +
//   公网域名 + 去 userinfo + 去内网/IP”的结构性约束；凡是内部可信来源的固定站点，
//   仍应优先走 safeExternalURL 白名单。

const maxBrowserURLLen = 4096

// BrowserURLError 描述一个不能交给浏览器打开的 URL，Code 稳定可用于测试与本地化。
type BrowserURLError struct {
	Code   string
	Detail string
}

func (e *BrowserURLError) Error() string {
	if e == nil {
		return ""
	}
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func browserURLError(code, detail string) *BrowserURLError {
	return &BrowserURLError{Code: code, Detail: detail}
}

// isPrivateOrLocalIP 判定一个 IP 是否属于本机 / 私网 / 链路本地 / 环回 / 未指定等
// 不应当让浏览器替启动器去访问的地址。
func isPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	// 云厂商链路本地元数据服务 169.254.169.254 已被 IsLinkLocalUnicast 覆盖；
	// 再显式拦一遍私有网段，兼容个别 IsPrivate 实现差异。
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127:
			return true // CGNAT 100.64.0.0/10
		case ip4[0] == 169 && ip4[1] == 254:
			return true
		case ip4[0] == 0:
			return true // 0.0.0.0/8 "本机网络"
		case ip4[0] >= 224:
			return true // 组播 / 保留
		}
		return false
	}
	// IPv6：唯一本地 fc00::/7、未指定 :: 等；环回 / 链路本地 / 组播已在开头覆盖。
	// net.IP 的 IsLoopback/IsPrivate 等方法会自动解包 IPv4-mapped（::ffff:a.b.c.d），
	// 无需手工处理映射。
	return ip.IsPrivate()
}

// looksLikeIPLiteral 报告 host 是否是用户直接填写的 IP 字面量（v4/v6/带括号 v6）。
func looksLikeIPLiteral(host string) bool {
	h := host
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if net.ParseIP(h) != nil {
		return true
	}
	return false
}

// ValidateBrowserURL 判定 raw 是否为一个可以安全交给系统浏览器打开的 https 公网 URL。
// 返回规范化后的 URL（去首尾空白），或 *BrowserURLError。
func ValidateBrowserURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", browserURLError("browser-url-empty", "URL 为空")
	}
	if len(raw) > maxBrowserURLLen {
		return "", browserURLError("browser-url-long", "URL 过长")
	}
	// 任何 ASCII 控制字符（含 CR/LF/Tab/NUL）都拒绝：这类字符交给系统打开器可能触发
	// 参数 / 协议行截断，绝不能出现在将要被“当一条 URL 解释”的字符串里。
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "", browserURLError("browser-url-control", "URL 含控制字符")
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", browserURLError("browser-url-parse", err.Error())
	}
	if u.Scheme != "https" {
		return "", browserURLError("browser-url-scheme", "只允许 https:// 链接")
	}
	if u.User != nil {
		return "", browserURLError("browser-url-userinfo", "链接不允许携带用户名/密码(userinfo)")
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return "", browserURLError("browser-url-no-host", "链接缺少主机名")
	}
	// 不允许用反斜杠 / @ 等做视觉混淆（url.Parse 已处理 @，这里再堵路径里的反斜杠）。
	if strings.ContainsAny(host, `\/'"`) {
		return "", browserURLError("browser-url-bad-host", "主机名含非法字符")
	}
	if port := u.Port(); port != "" && port != "443" {
		return "", browserURLError("browser-url-port", "只允许默认 443 端口")
	}

	if looksLikeIPLiteral(host) {
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if isPrivateOrLocalIP(ip) {
			return "", browserURLError("browser-url-internal-ip", "不允许打开指向本机/内网/链路本地的 IP 链接")
		}
		// 即使是公网 IP 字面量也拒绝：厂商下载页应以域名给出，直接打开 IP 常用于绕过
		// 域名认知做钓鱼，且不利于用户核对地址。
		return "", browserURLError("browser-url-ip-literal", "请使用域名链接而非裸 IP")
	}

	// 域名形态校验：必须含至少一个点、TLD 至少 2 个字母，标签合法。
	if !strings.Contains(host, ".") {
		return "", browserURLError("browser-url-single-label", "链接主机名缺少域名后缀")
	}
	labels := strings.Split(host, ".")
	for i, label := range labels {
		if label == "" {
			return "", browserURLError("browser-url-empty-label", "域名含空标签")
		}
		if i == len(labels)-1 {
			if len(label) < 2 {
				return "", browserURLError("browser-url-tld", "顶级域名长度异常")
			}
			for _, c := range label {
				if !((c >= 'a' && c <= 'z')) {
					return "", browserURLError("browser-url-tld-alpha", "顶级域名必须为字母")
				}
			}
			continue
		}
		if !isDomainLabel(label) {
			return "", browserURLError("browser-url-bad-label", "域名标签含非法字符")
		}
	}
	return raw, nil
}

// isDomainLabel 校验普通域名标签：字母数字与连字符，且不能以连字符开头/结尾。
func isDomainLabel(label string) bool {
	if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}

// BrowserOpenCommand 校验通过后，按平台构造打开默认浏览器的命令。调用方负责 Run。
// Windows 仍使用 rundll32 url.dll,FileProtocolHandler（不走 cmd /c，避免 shell 注入），
// URL 作为单个独立参数传入；darwin/linux 分别用 open / xdg-open。
func BrowserOpenCommand(raw string) (*exec.Cmd, error) {
	clean, err := ValidateBrowserURL(raw)
	if err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", clean), nil
	case "darwin":
		return exec.Command("open", clean), nil
	default:
		return exec.Command("xdg-open", clean), nil
	}
}

// runValidatedBrowserURL 是给“校验失败即放弃”场景的便捷封装：命令已由
// BrowserOpenCommand 构造（不含 shell），这里负责启动；需要隐藏窗口的调用方可直接
// 使用 BrowserOpenCommand 拿到 *exec.Cmd 后自行设置 SysProcAttr 再 Start。
func runValidatedBrowserURL(raw string) error {
	cmd, err := BrowserOpenCommand(raw)
	if err != nil {
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"externalopen", fmt.Sprintf("拦截不安全的浏览器打开请求: %v", err))
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("打开浏览器失败: %w", err)
	}
	return nil
}
