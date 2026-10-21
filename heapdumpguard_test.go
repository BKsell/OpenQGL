package main

import (
	"strings"
	"testing"
)

func TestHeapDumpGuard(t *testing.T) {
	lim := defaultHeapDumpLimits()
	root := `C:\Users\me\instances\demo\crash`

	t.Run("clean relative path", func(t *testing.T) {
		v := AuditHeapDumpArgs([]string{`-XX:HeapDumpPath=dumps\oom.hprof`}, root, lim)
		if !v.OK {
			t.Fatalf("expected ok, got %s", v.Reason)
		}
		if len(v.Entries) != 1 || v.Entries[0].Kind != "heapdump" {
			t.Fatalf("unexpected entries: %+v", v.Entries)
		}
	})

	t.Run("errorfile accepted", func(t *testing.T) {
		v := AuditHeapDumpArgs([]string{`-XX:ErrorFile=logs\hs_err.log`}, root, lim)
		if !v.OK {
			t.Fatalf("expected ok, got %s", v.Reason)
		}
	})

	t.Run("traversal blocked", func(t *testing.T) {
		for _, p := range []string{
			`..\..\Windows\System32\x.hprof`,
			`dumps\..\..\..\boot.ini`,
			`../etc/passwd`,
			`..\x.hprof`,
		} {
			v := AuditHeapDumpArgs([]string{"-XX:HeapDumpPath=" + p}, root, lim)
			if v.OK || v.Reason != "path-traversal" {
				t.Fatalf("path %q: expected path-traversal, got ok=%v reason=%s", p, v.OK, v.Reason)
			}
		}
	})

	t.Run("absolute and drive blocked", func(t *testing.T) {
		v := AuditHeapDumpArgs([]string{`-XX:HeapDumpPath=C:\Windows\Temp\x.hprof`}, root, lim)
		if v.OK || v.Reason != "drive-qualified" {
			t.Fatalf("expected drive-qualified, got ok=%v reason=%s", v.OK, v.Reason)
		}
		v = AuditHeapDumpArgs([]string{`-XX:HeapDumpPath=\\server\share\x.hprof`}, root, lim)
		if v.OK || v.Reason != "absolute-path" {
			t.Fatalf("expected absolute-path, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("device name blocked", func(t *testing.T) {
		for _, p := range []string{`NUL.hprof`, `dumps\CON`, `aux.txt`, `COM1.log`} {
			v := AuditHeapDumpArgs([]string{"-XX:ErrorFile=" + p}, root, lim)
			if v.OK || v.Reason != "device-name" {
				t.Fatalf("path %q: expected device-name, got ok=%v reason=%s", p, v.OK, v.Reason)
			}
		}
	})

	t.Run("env placeholder blocked", func(t *testing.T) {
		for _, p := range []string{`%APPDATA%\x.hprof`, `${HOME}/x.hprof`, `~/crash/x.log`} {
			v := AuditHeapDumpArgs([]string{"-XX:HeapDumpPath=" + p}, root, lim)
			if v.OK || v.Reason != "env-placeholder" {
				t.Fatalf("path %q: expected env-placeholder, got ok=%v reason=%s", p, v.OK, v.Reason)
			}
		}
	})

	t.Run("nul and control chars blocked", func(t *testing.T) {
		v := AuditHeapDumpArgs([]string{"-XX:HeapDumpPath=a\x00b.hprof"}, root, lim)
		if v.OK || v.Reason != "nul-byte" {
			t.Fatalf("expected nul-byte, got %s", v.Reason)
		}
		v = AuditHeapDumpArgs([]string{"-XX:HeapDumpPath=a\r\nb.hprof"}, root, lim)
		if v.OK || v.Reason != "control-char" {
			t.Fatalf("expected control-char, got %s", v.Reason)
		}
	})

	t.Run("outside root via join blocked", func(t *testing.T) {
		// 单个 ".." 段在 Clean 后仍逃逸根目录，由 outside-root 兜底。
		v := AuditHeapDumpArgs([]string{`-XX:HeapDumpPath=..\escape.hprof`}, root, lim)
		if v.OK {
			t.Fatalf("expected rejection, got ok")
		}
	})

	t.Run("too deep blocked", func(t *testing.T) {
		deep := `a\b\c\d\e\f\g\h\i\j.hprof`
		v := AuditHeapDumpArgs([]string{"-XX:HeapDumpPath=" + deep}, root, lim)
		if v.OK || v.Reason != "too-deep" {
			t.Fatalf("expected too-deep, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("too long blocked", func(t *testing.T) {
		long := strings.Repeat("a", 300) + ".hprof"
		v := AuditHeapDumpArgs([]string{"-XX:HeapDumpPath=" + long}, root, lim)
		if v.OK || v.Reason != "path-too-long" {
			t.Fatalf("expected path-too-long, got %s", v.Reason)
		}
	})

	t.Run("max entries enforced", func(t *testing.T) {
		args := []string{
			`-XX:HeapDumpPath=a.hprof`,
			`-XX:ErrorFile=b.log`,
			`-XX:HeapDumpPath=c.hprof`,
		}
		v := AuditHeapDumpArgs(args, root, lim)
		if v.OK || v.Reason != "too-many-entries" {
			t.Fatalf("expected too-many-entries, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("empty value skipped", func(t *testing.T) {
		v := AuditHeapDumpArgs([]string{"-XX:HeapDumpPath="}, root, lim)
		if !v.OK || len(v.Entries) != 0 {
			t.Fatalf("expected skip, got ok=%v entries=%d", v.OK, len(v.Entries))
		}
	})

	t.Run("unrelated args ignored", func(t *testing.T) {
		v := AuditHeapDumpArgs([]string{"-Xmx2G", "-Dfoo=bar", "-XX:+UseG1GC"}, root, lim)
		if !v.OK || len(v.Entries) != 0 {
			t.Fatalf("expected none, got %+v", v.Entries)
		}
	})

	t.Run("syntax only when root empty", func(t *testing.T) {
		// 不给根目录时仍应拒绝穿越 / 设备名，但不做 root 包含判定。
		v := AuditHeapDumpArgs([]string{`-XX:HeapDumpPath=dumps\a.hprof`}, "", lim)
		if !v.OK {
			t.Fatalf("expected ok without root, got %s", v.Reason)
		}
	})
}

func TestSummarizeHeapDumpVerdict(t *testing.T) {
	lim := defaultHeapDumpLimits()
	v := AuditHeapDumpArgs([]string{`-XX:HeapDumpPath=dumps\oom.hprof`}, `C:\r`, lim)
	s := SummarizeHeapDumpVerdict(v)
	if !strings.Contains(s, "heapdump=oom.hprof") && !strings.Contains(s, `heapdump=dumps\oom.hprof`) {
		t.Fatalf("unexpected summary: %s", s)
	}
	v2 := AuditHeapDumpArgs(nil, `C:\r`, lim)
	if s2 := SummarizeHeapDumpVerdict(v2); s2 != "heapdump: none" {
		t.Fatalf("unexpected none summary: %s", s2)
	}
	v3 := AuditHeapDumpArgs([]string{`-XX:HeapDumpPath=NUL`}, `C:\r`, lim)
	if s3 := SummarizeHeapDumpVerdict(v3); !strings.Contains(s3, "blocked:device-name") {
		t.Fatalf("unexpected blocked summary: %s", s3)
	}
}
