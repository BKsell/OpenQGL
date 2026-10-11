package main

// shortlinkguard.go —— 短链 / 重定向展开前的 SSRF 预检内核。
//
// 威胁模型：
//   启动器的镜像地址、版本清单 URL 等大多来自远端 JSON 或本地配置。若上游
//   被攻陷 / 配置被篡改，这些 URL 可能被换成短链（bit.ly、t.cn 等）或直接
//   指向内网地址。短链服务的“跳转目标”只有展开后才知道，而下载器一旦发起
//   HTTP 请求就会真的连到目标主机——这是 SSRF 的关键窗口：恶意目标可以指向
//   云元数据服务 169.254.169.254、内网主机、或本机回环，让启动器替攻击者
//   读取内网内容或探测端口。
//
//   本内核在“发起任何请求之前”做静态判定：
//     - 只允许 https 公网目标；http 明文一律拒绝（防止中间人改写跳转目标）；
//     - 非 http(s) 协议（file:/javascript:/data: 等）直接拒绝；
//     - IP 字面量（含八进制 / 十进制混淆写法）用 parseDestIP 还原后查
//       isPrivateOrLocalIP，私网 / 回环 / 链路本地 / 组播一律拒绝；
//     - 域名交给调用方注入的 resolver 解析（App 层用 net.LookupIP），任一
//       解析结果命中私网地址即拒绝；无法解析时按“宁严勿纵”拒绝；
//     - 跳转次数有上限（maxRedirectHops），防止无限重定向拖垮下载。
//
//   纯函数、不发起任何网络请求，全部判定可穷举测试。真正的网络请求仍由
//   secure_download 的流式下载器完成，本内核只负责“出发前的签证”。

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// maxRedirectHops 是展开短链时允许的最大跳转次数（含首次请求）。
const maxRedirectHops = 3

// shortenerHosts 是启动器可能遇到的知名短链服务主机表（去 www. 前缀后匹配）。
// 名单外的主机不享受“短链”特殊通道，但仍会被下面的协议 / 私网规则拦截。
var shortenerHosts = map[string]bool{
	"bit.ly":      true,
	"t.co":        true,
	"goo.gl":      true,
	"tinyurl.com": true,
	"is.gd":       true,
	"s.id":        true,
	"t.cn":        true,
	"dwz.cn":      true,
	"url.cn":      true,
	"u.nu":        true,
	"rb.gy":       true,
	"cutt.ly":     true,
	"shorte.st":   true,
	"suo.im":      true,
	"tiny.cc":     true,
	"shorturl.at": true,
	"v.gd":        true,
}

// HostResolver 把主机名解析成 IP 列表；nil 表示“无法解析”（保守拒绝）。
type HostResolver func(host string) ([]net.IP, error)

// knownShortenerHost 判断主机名是否属于已知短链服务。
func knownShortenerHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimPrefix(h, "www.")
	if h == "" {
		return false
	}
	return shortenerHosts[h]
}

// isShortLinkURL 报告 rawURL 是否解析自短链服务（解析失败返回 false）。
func isShortLinkURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	return knownShortenerHost(u.Host)
}

// redirectVerdict 是一次展开预检的结论。
type redirectVerdict struct {
	Blocked  bool   // true 表示必须拒绝
	Reason   string // 拒绝原因（Blocked 时）
	Resolved bool   // 是否成功解析到目标 IP（域名场景）
}

// verdictAllow 构造放行结论。
func verdictAllow() redirectVerdict { return redirectVerdict{} }

// verdictBlock 构造拒绝结论。
func verdictBlock(reason string) redirectVerdict {
	return redirectVerdict{Blocked: true, Reason: reason}
}

// classifyURLProtocol 校验协议并拒绝非 http(s)。返回规范化 URL 或错误。
func normalizeScheme(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("URL 为空")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("URL 无法解析: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		// 保留原样（禁止 userinfo：防止 user:pass@host 借短链夹带凭据）。
		if u.User != nil {
			return "", fmt.Errorf("URL 不允许携带 userinfo")
		}
		return rawURL, nil
	case "http":
		return "", fmt.Errorf("短链 / 重定向目标必须是 https，拒绝明文 http")
	case "file", "javascript", "data", "vbscript":
		return "", fmt.Errorf("拒绝协议 %s 的 URL", u.Scheme)
	default:
		return "", fmt.Errorf("不支持的协议: %s", u.Scheme)
	}
}

// verdictForHost 判定单个主机名是否安全（IP 字面量直接判定，域名走 resolver）。
func verdictForHost(host string, resolve HostResolver) redirectVerdict {
	host = strings.TrimSpace(host)
	if host == "" {
		return verdictBlock("目标主机为空")
	}
	// 去掉 IPv6 括号与作用域，交给 parseDestIP 识别 IP 字面量。
	ip, isIP := parseDestIP(host)
	if isIP {
		if isPrivateOrLocalIP(ip) {
			return verdictBlock("目标解析到私网 / 回环 / 链路本地地址: " + host)
		}
		return verdictAllow()
	}
	if resolve == nil {
		return verdictBlock("无法解析目标主机（未配置解析器），宁严勿纵: " + host)
	}
	ips, err := resolve(host)
	if err != nil || len(ips) == 0 {
		return verdictBlock("目标主机解析失败，宁严勿纵: " + host)
	}
	for _, ip := range ips {
		if isPrivateOrLocalIP(ip) {
			return verdictBlock("目标主机解析到私网地址: " + host + " -> " + ip.String())
		}
	}
	return verdictAllow()
}

// guardRedirectTarget 对展开后的目标 URL 做完整预检；rawURL 已通过协议校验。
func guardRedirectTarget(rawURL string, resolve HostResolver) redirectVerdict {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return verdictBlock("目标 URL 无法解析主机")
	}
	if u.User != nil {
		return verdictBlock("目标 URL 不允许携带 userinfo")
	}
	return verdictForHost(u.Host, resolve)
}

// preflightShortLink 是短链场景的完整预检：
//  1. 协议白名单（https 且无 userinfo）；
//  2. 目标主机私网判定；
//  3. 跳转次数预算。
//
// 返回规范化后的原始 URL（未展开，展开仍由下载器跟随重定向，但每跳都会
// 经过 Guard 校验；此处先拦住“第一跳”）。
func preflightShortLink(rawURL string, hops int, resolve HostResolver) (string, error) {
	if hops < 0 || hops > maxRedirectHops {
		return "", fmt.Errorf("重定向跳数超过上限 %d", maxRedirectHops)
	}
	norm, err := normalizeScheme(rawURL)
	if err != nil {
		return "", err
	}
	if !isShortLinkURL(norm) {
		// 非短链的普通 https 公网 URL 不额外折腾（私网拦截在 netaddrguard /
		// 下载器既有防线里处理），这里只保证协议与 userinfo 合规。
		return norm, nil
	}
	if v := guardRedirectTarget(norm, resolve); v.Blocked {
		return "", fmt.Errorf("短链目标预检拒绝: %s", v.Reason)
	}
	return norm, nil
}

// preflightRedirectHop 校验重定向链上的一跳（跟随 Location 前调用）：
// 目标必须是 https 公网且不指向私网；hops 为该跳序号（从 1 开始）。
func preflightRedirectHop(targetURL string, hops int, resolve HostResolver) error {
	if hops > maxRedirectHops {
		return fmt.Errorf("重定向跳数超过上限 %d", maxRedirectHops)
	}
	norm, err := normalizeScheme(targetURL)
	if err != nil {
		return err
	}
	if v := guardRedirectTarget(norm, resolve); v.Blocked {
		return fmt.Errorf("重定向目标预检拒绝: %s", v.Reason)
	}
	return nil
}

// netLookupResolver 是 App 层可注入的真实解析器（net.LookupIP）。
func netLookupResolver(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

// preflightDownloadURL 是 secure_download 接线入口：任何下载 URL 出发前先过
// 短链预检。非短链 URL 只做协议 / userinfo 校验，开销极小；短链 URL 追加
// 主机私网判定。resolve 为空时使用 net.LookupIP（会真实发 DNS，仅域名场景）。
func preflightDownloadURL(rawURL string, resolve HostResolver) (string, error) {
	if resolve == nil {
		resolve = netLookupResolver
	}
	return preflightShortLink(rawURL, 0, resolve)
}
