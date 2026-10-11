package main

import (
	"net"
	"testing"
)

// shortlinkguard_test.go —— 短链预检内核的穷举测试：协议白名单、私网 IP 判定
// （含混淆写法）、域名解析判定、跳数上限。全部用假 resolver，不发起真实网络。

// fakeResolver 让指定主机解析到给定 IP 列表；未登记的主机返回解析失败。
func fakeResolver(mapping map[string][]net.IP) HostResolver {
	return func(host string) ([]net.IP, error) {
		if ips, ok := mapping[host]; ok {
			return ips, nil
		}
		return nil, net.UnknownNetworkError("no such host: " + host)
	}
}

func ip(s string) net.IP { return net.ParseIP(s) }

func TestKnownShortenerHost(t *testing.T) {
	yes := []string{"bit.ly", "www.t.cn", "tinyurl.com", "t.CO", "Bit.Ly", "dwz.cn"}
	for _, h := range yes {
		if !knownShortenerHost(h) {
			t.Fatalf("knownShortenerHost(%q) = false, want true", h)
		}
	}
	no := []string{"example.com", "localhost", "", "bit.ly.evil.com", "notbitly.com"}
	for _, h := range no {
		if knownShortenerHost(h) {
			t.Fatalf("knownShortenerHost(%q) = true, want false", h)
		}
	}
}

func TestIsShortLinkURL(t *testing.T) {
	if !isShortLinkURL("https://t.cn/abc") {
		t.Fatal("t.cn should be a short link")
	}
	if isShortLinkURL("https://example.com/x") {
		t.Fatal("example.com should not be a short link")
	}
	if isShortLinkURL("") {
		t.Fatal("empty should not be a short link")
	}
}

func TestNormalizeScheme(t *testing.T) {
	// 合法 https。
	if _, err := normalizeScheme("https://example.com/x"); err != nil {
		t.Fatalf("https rejected: %v", err)
	}
	// http 明文拒绝。
	if _, err := normalizeScheme("http://example.com/x"); err == nil {
		t.Fatal("http should be rejected")
	}
	// 危险协议拒绝。
	for _, p := range []string{"file:///etc/passwd", "javascript:alert(1)", "data:text/html,<b>x", "vbscript:x"} {
		if _, err := normalizeScheme(p); err == nil {
			t.Fatalf("protocol %q should be rejected", p)
		}
	}
	// userinfo 拒绝。
	if _, err := normalizeScheme("https://user:pass@example.com/x"); err == nil {
		t.Fatal("userinfo should be rejected")
	}
	// 空 / 无法解析。
	if _, err := normalizeScheme("   "); err == nil {
		t.Fatal("empty should be rejected")
	}
	if _, err := normalizeScheme("://bad"); err == nil {
		t.Fatal("unparseable should be rejected")
	}
}

func TestVerdictForHost(t *testing.T) {
	noResolve := HostResolver(nil)
	// IP 字面量私网判定（不需要 resolver）。
	private := []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", "0.0.0.0", "::1", "fe80::1", "2130706433", // 十进制混淆 127.0.0.1
	}
	for _, h := range private {
		if v := verdictForHost(h, noResolve); !v.Blocked {
			t.Fatalf("private host %q not blocked", h)
		}
	}
	// 公网 IP 字面量放行。
	public := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
	for _, h := range public {
		if v := verdictForHost(h, noResolve); v.Blocked {
			t.Fatalf("public host %q blocked: %s", h, v.Reason)
		}
	}
	// 无 resolver 的域名：宁严勿纵。
	if v := verdictForHost("example.com", noResolve); !v.Blocked {
		t.Fatal("domain without resolver should be blocked")
	}
	// resolver 解析到私网：拒绝。
	bad := fakeResolver(map[string][]net.IP{"internal.example": {ip("10.1.2.3"), ip("8.8.8.8")}})
	if v := verdictForHost("internal.example", bad); !v.Blocked {
		t.Fatal("mixed private/public resolution should be blocked")
	}
	// resolver 解析到公网：放行。
	good := fakeResolver(map[string][]net.IP{"public.example": {ip("8.8.8.8"), ip("1.1.1.1")}})
	if v := verdictForHost("public.example", good); v.Blocked {
		t.Fatalf("public domain blocked: %s", v.Reason)
	}
	// 解析失败：拒绝。
	fail := fakeResolver(map[string][]net.IP{})
	if v := verdictForHost("ghost.example", fail); !v.Blocked {
		t.Fatal("unresolvable domain should be blocked")
	}
}

func TestPreflightShortLink(t *testing.T) {
	resolve := fakeResolver(map[string][]net.IP{
		"public.example": {ip("8.8.8.8")},
		"t.cn":           {ip("8.8.8.8")}, // 短链域本身解析到公网
	})

	// 短链 + 公网目标：放行。
	raw := "https://t.cn/abc"
	if _, err := preflightShortLink(raw, 0, resolve); err != nil {
		t.Fatalf("public short link rejected: %v", err)
	}
	// 短链 + 私网目标：拒绝。
	raw = "https://t.cn/x"
	priv := fakeResolver(map[string][]net.IP{"t.cn": {ip("127.0.0.1")}})
	if _, err := preflightShortLink(raw, 0, priv); err == nil {
		t.Fatal("short link to loopback should be rejected")
	}
	// 非短链 https 公网 URL：只做协议校验，原样通过。
	if _, err := preflightShortLink("https://example.com/x", 0, nil); err != nil {
		t.Fatalf("plain https rejected: %v", err)
	}
	// 非短链 http：拒绝。
	if _, err := preflightShortLink("http://example.com/x", 0, nil); err == nil {
		t.Fatal("plain http should be rejected")
	}
	// 跳数越界：拒绝。
	if _, err := preflightShortLink("https://t.cn/abc", maxRedirectHops+1, resolve); err == nil {
		t.Fatal("hop overrun should be rejected")
	}
	// 负数跳数：拒绝。
	if _, err := preflightShortLink("https://t.cn/abc", -1, resolve); err == nil {
		t.Fatal("negative hops should be rejected")
	}
}

func TestPreflightRedirectHop(t *testing.T) {
	resolve := fakeResolver(map[string][]net.IP{"public.example": {ip("8.8.8.8")}})
	// 第 1 跳公网：放行。
	if err := preflightRedirectHop("https://public.example/final", 1, resolve); err != nil {
		t.Fatalf("public hop rejected: %v", err)
	}
	// 超上限跳数：拒绝。
	if err := preflightRedirectHop("https://public.example/final", maxRedirectHops+1, resolve); err == nil {
		t.Fatal("hop overrun should be rejected")
	}
	// 目标私网：拒绝。
	priv := fakeResolver(map[string][]net.IP{"meta.example": {ip("169.254.169.254")}})
	if err := preflightRedirectHop("https://meta.example/x", 1, priv); err == nil {
		t.Fatal("private hop should be rejected")
	}
	// 非 https：拒绝。
	if err := preflightRedirectHop("http://public.example/x", 1, resolve); err == nil {
		t.Fatal("http hop should be rejected")
	}
}

func TestPreflightDownloadURL(t *testing.T) {
	// 下载入口默认走真实 DNS 解析器——这里只测协议层行为（非短链不解析）。
	if _, err := preflightDownloadURL("https://example.com/file.zip", nil); err != nil {
		t.Fatalf("plain https download rejected: %v", err)
	}
	if _, err := preflightDownloadURL("http://example.com/file.zip", nil); err == nil {
		t.Fatal("http download should be rejected")
	}
	if _, err := preflightDownloadURL("file:///etc/passwd", nil); err == nil {
		t.Fatal("file download should be rejected")
	}
	// 注入自定义 resolver 后，短链到私网必须被拦。
	priv := fakeResolver(map[string][]net.IP{"t.cn": {ip("10.0.0.1")}})
	if _, err := preflightDownloadURL("https://t.cn/zip", priv); err == nil {
		t.Fatal("short link to private should be rejected at download entry")
	}
}
