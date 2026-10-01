package main

import (
	"testing"
	"time"
)

func TestClampPollInterval(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want time.Duration
	}{
		{"zero falls back to min", 0, deviceCodeMinInterval},
		{"negative falls back to min", -3, deviceCodeMinInterval},
		{"below min", 1, deviceCodeMinInterval},
		{"normal value kept", 17, 17 * time.Second},
		{"boundary min", 5, 5 * time.Second},
		{"huge value capped", 999999, deviceCodeMaxInterval},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := clampPollInterval(c.in); got != c.want {
				t.Fatalf("clampPollInterval(%d) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestClampDeviceTTL(t *testing.T) {
	if got := clampDeviceTTL(0); got != deviceCodeDefaultTTL {
		t.Fatalf("zero ttl = %v, want default %v", got, deviceCodeDefaultTTL)
	}
	if got := clampDeviceTTL(-60); got != deviceCodeDefaultTTL {
		t.Fatalf("negative ttl = %v, want default %v", got, deviceCodeDefaultTTL)
	}
	if got := clampDeviceTTL(900); got != 15*time.Minute {
		t.Fatalf("normal ttl = %v, want 15m", got)
	}
	if got := clampDeviceTTL(86400); got != deviceCodeMaxTTL {
		t.Fatalf("huge ttl = %v, want cap %v", got, deviceCodeMaxTTL)
	}
}

func TestTokenExpiryUnix(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	base := now.Add(24 * time.Hour).Unix()

	if got := tokenExpiryUnix(now, 86400); got != base {
		t.Fatalf("normal expiry = %d, want %d", got, base)
	}
	// 非正值回退 24h，而不是"现在"（那会立刻被判成过期）。
	if got := tokenExpiryUnix(now, 0); got != base {
		t.Fatalf("zero expiry = %d, want fallback %d", got, base)
	}
	if got := tokenExpiryUnix(now, -5); got != base {
		t.Fatalf("negative expiry = %d, want fallback %d", got, base)
	}
	// 超大值钳到一年。
	want := now.Add(time.Duration(tokenMaxLifetimeSeconds) * time.Second).Unix()
	if got := tokenExpiryUnix(now, 999_999_999); got != want {
		t.Fatalf("huge expiry = %d, want cap %d", got, want)
	}
}

func TestIsAllowedVerificationURL(t *testing.T) {
	allow := []string{
		"https://www.microsoft.com/link",
		"https://microsoft.com/link",
		"https://login.live.com/oauth20_remoteconnect.srf",
		"https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode",
	}
	for _, u := range allow {
		if !isAllowedVerificationURL(u) {
			t.Errorf("expected allowed: %s", u)
		}
	}

	deny := []string{
		"http://www.microsoft.com/link",                       // 明文 http
		"https://micr0soft.com/link",                          // 拼写近似的钓鱼域
		"https://microsoft.com.evil.com/link",                 // 后缀伪造
		"https://evil.com/link",                               // 完全无关主机
		"https://www.microsoft.com@evil.com/link",             // userinfo 视觉混淆
		"javascript:alert(1)",                                 // 非 http(s)
		"file:///C:/Windows/System32/",                        // 本地文件
		"",                                                    // 空
		"https://127.0.0.1/link",                              // 回环 IP（非微软主机）
		"https://10.0.0.5/link",                               // 内网 IP
	}
	for _, u := range deny {
		if isAllowedVerificationURL(u) {
			t.Errorf("expected denied: %q", u)
		}
	}
}
