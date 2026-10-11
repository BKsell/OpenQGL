package main

import (
	"strings"
	"testing"
)

func TestParseProxyArgs(t *testing.T) {
	lim := defaultProxyLimits()

	t.Run("clean public proxy", func(t *testing.T) {
		args := []string{
			"-Xmx2G",
			"-Dhttp.proxyHost=proxy.example.com",
			"-Dhttp.proxyPort=8080",
			"-Dhttps.proxyHost=proxy.example.com",
		}
		v := ParseProxyArgs(args, lim)
		if !v.OK {
			t.Fatalf("expected ok, got %s", v.Reason)
		}
		if len(v.Entries) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(v.Entries))
		}
		if v.Entries[0].Scheme != "http" || v.Entries[0].Host != "proxy.example.com" || v.Entries[0].Port != 8080 {
			t.Fatalf("unexpected entry: %+v", v.Entries[0])
		}
	})

	t.Run("loopback blocked", func(t *testing.T) {
		v := ParseProxyArgs([]string{"-Dhttp.proxyHost=127.0.0.1"}, lim)
		if v.OK || v.Reason != "host-not-public" {
			t.Fatalf("expected host-not-public, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("private range blocked", func(t *testing.T) {
		for _, h := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "fe80::1"} {
			v := ParseProxyArgs([]string{"-Dhttps.proxyHost=" + h}, lim)
			if v.OK || v.Reason != "host-not-public" {
				t.Fatalf("host %s: expected host-not-public, got ok=%v reason=%s", h, v.OK, v.Reason)
			}
		}
	})

	t.Run("obfuscated ipv4 blocked", func(t *testing.T) {
		v := ParseProxyArgs([]string{"-DsocksProxyHost=2130706433"}, lim)
		if v.OK || v.Reason != "host-not-public" {
			t.Fatalf("expected host-not-public for obfuscated ip, got %s", v.Reason)
		}
	})

	t.Run("control chars blocked", func(t *testing.T) {
		v := ParseProxyArgs([]string{"-Dhttp.proxyHost=evil.example.com\r\nX: y"}, lim)
		if v.OK || v.Reason != "host-control-chars" {
			t.Fatalf("expected host-control-chars, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("sensitive port blocked", func(t *testing.T) {
		v := ParseProxyArgs([]string{"-Dhttp.proxyHost=proxy.example.com", "-Dhttp.proxyPort=22"}, lim)
		if v.OK || v.Reason != "bad-port" {
			t.Fatalf("expected bad-port, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("out of range port blocked", func(t *testing.T) {
		v := ParseProxyArgs([]string{"-Dhttp.proxyHost=proxy.example.com", "-Dhttp.proxyPort=70000"}, lim)
		if v.OK || v.Reason != "bad-port" {
			t.Fatalf("expected bad-port, got %s", v.Reason)
		}
	})

	t.Run("max entries enforced", func(t *testing.T) {
		small := ProxyLimits{MaxValueLen: 512, MaxHostLen: 253, MaxEntries: 2}
		args := []string{
			"-Dhttp.proxyHost=a.example.com",
			"-Dhttps.proxyHost=b.example.com",
			"-DsocksProxyHost=c.example.com",
		}
		v := ParseProxyArgs(args, small)
		if v.OK || v.Reason != "too-many-proxies" {
			t.Fatalf("expected too-many-proxies, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("doc range ipv6 treated as non public", func(t *testing.T) {
		v := ParseProxyArgs([]string{"-Dhttp.proxyHost=2001:db8::1"}, lim)
		if v.OK || v.Reason != "host-not-public" {
			t.Fatalf("expected host-not-public for doc range, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("empty value skipped", func(t *testing.T) {
		v := ParseProxyArgs([]string{"-Dhttp.proxyHost="}, lim)
		if !v.OK || len(v.Entries) != 0 {
			t.Fatalf("expected ok with no entries, got ok=%v entries=%d", v.OK, len(v.Entries))
		}
	})

	t.Run("no proxy args", func(t *testing.T) {
		v := ParseProxyArgs([]string{"-Xmx2G", "-Djava.library.path=x"}, lim)
		if !v.OK || len(v.Entries) != 0 {
			t.Fatalf("expected ok with none, got %+v", v.Entries)
		}
	})
}

func TestSplitProxyHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port string
	}{
		{"proxy.example.com", "proxy.example.com", ""},
		{"proxy.example.com:8080", "proxy.example.com", "8080"},
		{"[2001:db8::1]:3128", "2001:db8::1", "3128"},
		{"[2001:db8::1]", "2001:db8::1", ""},
		{"host:8080:extra", "host:8080", "extra"},
	}
	for _, c := range cases {
		h, p := splitProxyHostPort(c.in)
		if h != c.host || p != c.port {
			t.Fatalf("split(%q) = (%q,%q), want (%q,%q)", c.in, h, p, c.host, c.port)
		}
	}
}

func TestSummarizeProxyVerdict(t *testing.T) {
	lim := defaultProxyLimits()
	v := ParseProxyArgs([]string{"-Dhttp.proxyHost=proxy.example.com", "-Dhttp.proxyPort=8080"}, lim)
	s := SummarizeProxyVerdict(v)
	if !strings.Contains(s, "http://proxy.example.com:8080") {
		t.Fatalf("unexpected summary: %s", s)
	}
	v2 := ParseProxyArgs([]string{"-Dhttp.proxyHost=127.0.0.1"}, lim)
	if s2 := SummarizeProxyVerdict(v2); !strings.Contains(s2, "blocked:host-not-public") {
		t.Fatalf("unexpected blocked summary: %s", s2)
	}
	v3 := ParseProxyArgs(nil, lim)
	if s3 := SummarizeProxyVerdict(v3); s3 != "proxy: none" {
		t.Fatalf("unexpected none summary: %s", s3)
	}
}
