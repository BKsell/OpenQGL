package main

import (
	"net"
	"testing"
)

func TestParseIPPiece(t *testing.T) {
	cases := []struct {
		in  string
		val int64
		ok  bool
	}{
		{"0", 0, true},
		{"127", 127, true},
		{"255", 255, true},
		{"0x7f", 127, true},
		{"0X7F", 127, true},
		{"0o177", 127, true},
		{"0177", 127, true}, // 前导 0 按八进制
		{"089", 89, true},   // 非法八进制回退十进制
		{"", 0, false},
		{"0x", 0, false},
		{"12a", 0, false},
		{"-1", 0, false},
	}
	for _, c := range cases {
		v, ok := parseIPPiece(c.in)
		if ok != c.ok || (ok && v != c.val) {
			t.Errorf("parseIPPiece(%q) = (%d,%v), want (%d,%v)", c.in, v, ok, c.val, c.ok)
		}
	}
}

func TestParseDestIPObfuscatedLoopback(t *testing.T) {
	// 这些写法建连时全部等价于 127.0.0.1，必须都能还原出来并被内网守卫拦下。
	hosts := []string{
		"127.0.0.1",
		"127.0.1",
		"127.1",
		"0x7f.0.0.1",
		"0x7f.0.1",
		"0x7f.1",
		"0177.0.0.1",
		"0x7f000001",
		"0X7F000001",
		"2130706433",
		"017700000001",
		"127.0.0.1.",
	}
	for _, h := range hosts {
		ip, ok := parseDestIP(h)
		if !ok {
			t.Fatalf("parseDestIP(%q) 未识别为 IP 字面量", h)
		}
		if ip.String() != "127.0.0.1" {
			t.Fatalf("parseDestIP(%q) = %s, want 127.0.0.1", h, ip.String())
		}
		if !isBlockedIP(ip) {
			t.Fatalf("还原后的回环地址 %s (%q) 未被拦截", ip.String(), h)
		}
	}
}

func TestParseDestIPPrivateRanges(t *testing.T) {
	// RFC1918 / 链路本地 / 本网络段，含非规范写法。
	blocked := map[string]string{
		"10.0.0.1":         "10.0.0.1",
		"012.0.0.1":        "10.0.0.1", // 前导 0 八进制
		"172.16.5.4":       "172.16.5.4",
		"192.168.1.1":      "192.168.1.1",
		"169.254.169.254":  "169.254.169.254",
		"0.0.0.0":          "0.0.0.0",
		"0.1.2.3":          "0.1.2.3", // 0.0.0.0/8 本网络段
		"0":                "0.0.0.0",
		"::1":              "::1",
		"::":               "::",
		"::ffff:127.0.0.1": "127.0.0.1",
		"::ffff:7f00:1":    "127.0.0.1",
		"::ffff:2130706433": "127.0.0.1",
		"::ffff:0x7f.1":    "127.0.0.1",
		"fe80::1":          "fe80::1",
		"fc00::1":          "fc00::1",
	}
	for in, want := range blocked {
		ip, ok := parseDestIP(in)
		if !ok {
			t.Fatalf("parseDestIP(%q) 未识别", in)
		}
		if ip.String() != want {
			t.Fatalf("parseDestIP(%q) = %s, want %s", in, ip.String(), want)
		}
		if !isBlockedIP(ip) {
			t.Fatalf("%s (%q) 应当被 isBlockedIP 拦截", ip.String(), in)
		}
	}
}

func TestParseDestIPPublic(t *testing.T) {
	// 公网地址的规范与非规范写法都应可解析且不被内网守卫误伤。
	cases := map[string]string{
		"8.8.8.8":          "8.8.8.8",
		"1.1.1.1":          "1.1.1.1",
		"9.9.9.9":          "9.9.9.9",
		"172.32.0.1":       "172.32.0.1", // 紧邻 RFC1918 但属于公网
		"0x08080808":       "8.8.8.8",
		"134744072":        "8.8.8.8",
		"8.9":              "8.0.0.9",
		"::ffff:8.8.8.8":   "8.8.8.8",
		"2606:4700::1111":  "2606:4700::1111",
		"2001:4860:4860::8888": "2001:4860:4860::8888",
	}
	for in, want := range cases {
		ip, ok := parseDestIP(in)
		if !ok {
			t.Fatalf("parseDestIP(%q) 未识别", in)
		}
		if ip.String() != want {
			t.Fatalf("parseDestIP(%q) = %s, want %s", in, ip.String(), want)
		}
		if isBlockedIP(ip) {
			t.Fatalf("公网地址 %s (%q) 被错误拦截", ip.String(), in)
		}
	}
}

func TestParseDestIPNonLiterals(t *testing.T) {
	// 域名 / 非法编码一律不当成 IP，留给 DNS 与建连层处理。
	domains := []string{
		"localhost",
		"example.com",
		"libraries.minecraft.net",
		"10.example.0.1",
		"a.1.2.3",
		"1.2.3.4.5",
		"999.0.0.1",
		"1.2.300.4",
		"0x",
		"256.1",
		"",
	}
	for _, d := range domains {
		if ip, ok := parseDestIP(d); ok {
			t.Fatalf("parseDestIP(%q) 误判为 IP: %s", d, ip.String())
		}
	}
}

func TestIsPrivateDestObfuscated(t *testing.T) {
	// 字符串态 SSRF 守卫必须拦住非规范内网字面量。
	for _, h := range []string{
		"http://2130706433/latest/version",
		"http://0x7f000001/",
		"http://0177.0.0.1:8080/",
		"http://[::ffff:7f00:1]/",
	} {
		// 注意：url.Parse 会保留方括号，parseDestIP 以 Hostname()（去括号）为准。
		if !isPrivateDest(h) {
			t.Fatalf("isPrivateDest(%q) 未拦截", h)
		}
	}
	if isPrivateDest("https://libraries.minecraft.net/path") {
		t.Fatal("正常公网域名被误判为内网目标")
	}
	if isPrivateDest("https://8.8.8.8/") {
		t.Fatal("公网 IP 被误判为内网目标")
	}
}

func TestZeroNetworkIPv4(t *testing.T) {
	if !isZeroNetworkIPv4(net.ParseIP("0.1.2.3")) {
		t.Fatal("0.1.2.3 应判定为 0.0.0.0/8")
	}
	if isZeroNetworkIPv4(net.ParseIP("1.2.3.4")) {
		t.Fatal("1.2.3.4 不属于 0.0.0.0/8")
	}
	if isZeroNetworkIPv4(net.ParseIP("::1")) {
		t.Fatal("IPv6 回环不应命中 IPv4 本网络段判定")
	}
}
