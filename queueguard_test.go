package main

import (
	"strings"
	"testing"
)

func TestQueueGuardValidateURL(t *testing.T) {
	lim := defaultQueueLimits()
	good := []string{
		"https://launcher.mojang.com/v1/objects/x/client.jar",
		"https://piston-meta.mojang.com/mc/game/version_manifest.json",
		"http://bmclapi2.bangbang93.com/version/1.20.1",
		"https://cdn.modrinth.com/data/proj/versions/v.jar",
	}
	for _, s := range good {
		if r := validateQueueURL(s, lim); r != "" {
			t.Fatalf("%q rejected: %s", s, r)
		}
	}
	bad := []struct{ in, want string }{
		{"ftp://launcher.mojang.com/x", "url-scheme"},
		{"https://user:pass@launcher.mojang.com/x", "url-userinfo"},
		{"https://evil.com/x.jar", "url-host:"},
		{"https://launcher.mojang.com:9999/x", "url-host:"},
		{"https://192.168.1.1/x", "url-host:"},
		{"", "url-parse-fail"},
	}
	for _, c := range bad {
		r := validateQueueURL(c.in, lim)
		if r == "" || !strings.Contains(r, c.want) {
			t.Fatalf("%q: got %q want %q", c.in, r, c.want)
		}
	}
}

func TestQueueGuardValidateDest(t *testing.T) {
	lim := defaultQueueLimits()
	good := []string{"libraries/net/minecraft/client-1.20.1.jar", "versions/1.20.1/1.20.1.json", "a/b/c.jar"}
	for _, s := range good {
		if r := validateQueueDest(s, lim); r != "" {
			t.Fatalf("%q rejected: %s", s, r)
		}
	}
	bad := []struct{ in, want string }{
		{"../evil.jar", "dest-dotdot"},
		{"/abs.jar", "dest-absolute"},
		{"C:evil.jar", "dest-absolute"},
		{"a\\b.jar", "dest-backslash"},
		{"", "dest-empty"},
	}
	for _, c := range bad {
		r := validateQueueDest(c.in, lim)
		if r == "" || !strings.Contains(r, c.want) {
			t.Fatalf("%q: got %q want %q", c.in, r, c.want)
		}
	}
}

func TestQueueGuardHash(t *testing.T) {
	if r := validateQueueHash(""); r != "" {
		t.Fatalf("empty hash rejected: %s", r)
	}
	if r := validateQueueHash(strings.Repeat("a", 40)); r != "" {
		t.Fatalf("sha1 rejected: %s", r)
	}
	if r := validateQueueHash(strings.Repeat("A", 64)); r != "" {
		t.Fatalf("sha256 rejected: %s", r)
	}
	for _, h := range []string{strings.Repeat("a", 41), "zz" + strings.Repeat("a", 38), "x"} {
		if r := validateQueueHash(h); r == "" {
			t.Fatalf("%q accepted", h)
		}
	}
}

func TestAuditDownloadQueue(t *testing.T) {
	lim := defaultQueueLimits()
	good := []queueItem{
		{URL: "https://launcher.mojang.com/v1/objects/a/client.jar", Dest: "versions/1.20.1/1.20.1.jar", Hash: strings.Repeat("a", 40), Size: 1000},
		{URL: "https://cdn.modrinth.com/data/x/y.jar", Dest: "mods/y.jar", Size: 500},
	}
	vd := AuditDownloadQueue(good, lim)
	if !vd.OK {
		t.Fatalf("good rejected: %s", vd.Reason)
	}
	if len(vd.Clean) != 2 || vd.Total != 1500 {
		t.Fatalf("clean=%d total=%d", len(vd.Clean), vd.Total)
	}
	bad := []struct {
		name string
		it   queueItem
		want string
	}{
		{"ssrf", queueItem{URL: "https://10.0.0.1/x", Dest: "a.jar"}, "url-host:"},
		{"dest-escape", queueItem{URL: "https://launcher.mojang.com/x", Dest: "../evil.jar"}, "dest-dotdot"},
		{"hash", queueItem{URL: "https://launcher.mojang.com/x", Dest: "a.jar", Hash: "zz"}, "hash"},
		{"neg-size", queueItem{URL: "https://launcher.mojang.com/x", Dest: "a.jar", Size: -1}, "size-negative"},
	}
	for _, c := range bad {
		vd := AuditDownloadQueue([]queueItem{c.it}, lim)
		if vd.OK || !strings.Contains(vd.Reason, c.want) {
			t.Fatalf("%s: ok=%v reason=%q", c.name, vd.OK, vd.Reason)
		}
	}
}

func TestSummarizeQueueVerdict(t *testing.T) {
	if s := SummarizeQueueVerdict(queueVerdict{OK: true, Total: 2 << 20}); s != "queue ok entries=0 totalMB=2" {
		t.Fatalf("summary wrong: %q", s)
	}
	if s := SummarizeQueueVerdict(queueVerdict{OK: false, Reason: "url-host:evil.com"}); s != "queue bad url-host:evil.com" {
		t.Fatalf("summary wrong: %q", s)
	}
}
