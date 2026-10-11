package main

import (
	"strings"
	"testing"
)

func TestPatchManifestGood(t *testing.T) {
	lim := defaultPatchLimits()
	raw := `[
	  {"action":"add","file":"libraries/a/b-1.jar","hash":"` + strings.Repeat("a", 40) + `","size":1024},
	  {"action":"replace","file":"config/options.txt","size":100},
	  {"action":"remove","file":"old.jar"}
	]`
	vd := ValidatePatchManifest([]byte(raw), lim)
	if !vd.OK {
		t.Fatalf("good rejected: %s", vd.Reason)
	}
	if vd.Total != 3 || vd.Bytes != 1124 {
		t.Fatalf("total=%d bytes=%d", vd.Total, vd.Bytes)
	}
}

func TestPatchManifestBad(t *testing.T) {
	lim := defaultPatchLimits()
	bad := []struct {
		name string
		raw  string
		want string
	}{
		{"action", `[{"action":"delete","file":"a"}]`, "action:delete"},
		{"abs", `[{"action":"add","file":"/etc/a"}]`, "file-absolute"},
		{"dotdot", `[{"action":"add","file":"../a"}]`, "file-dotdot"},
		{"backslash", `[{"action":"add","file":"a\\b"}]`, "file-backslash"},
		{"hash", `[{"action":"add","file":"a","hash":"zz"}]`, "hash:"},
		{"neg-size", `[{"action":"add","file":"a","size":-2}]`, "size-negative"},
		{"dup", `[{"action":"add","file":"a"},{"action":"remove","file":"a"}]`, "dup:a:"},
		{"parse", `[{"action":"add"`, "parse-fail"},
	}
	for _, c := range bad {
		vd := ValidatePatchManifest([]byte(c.raw), lim)
		if vd.OK || !strings.Contains(vd.Reason, c.want) {
			t.Fatalf("%s: ok=%v reason=%q want %q", c.name, vd.OK, vd.Reason, c.want)
		}
	}
}

func TestPatchManifestOverflow(t *testing.T) {
	lim := defaultPatchLimits()
	lim.MaxEntries = 2
	raw := `[{"action":"add","file":"a"},{"action":"add","file":"b"},{"action":"add","file":"c"}]`
	vd := ValidatePatchManifest([]byte(raw), lim)
	if vd.OK || vd.Reason != "entries-overflow" {
		t.Fatalf("overflow: ok=%v reason=%q", vd.OK, vd.Reason)
	}
	lim = defaultPatchLimits()
	lim.MaxTotalSize = 10
	raw = `[{"action":"add","file":"a","size":100}]`
	vd = ValidatePatchManifest([]byte(raw), lim)
	if vd.OK || vd.Reason != "total-overflow" {
		t.Fatalf("total: ok=%v reason=%q", vd.OK, vd.Reason)
	}
}

func TestSummarizePatchVerdict(t *testing.T) {
	if s := SummarizePatchVerdict(patchVerdict{OK: true, Total: 2, Bytes: 5}); s != "patch ok entries=2 bytes=5" {
		t.Fatalf("summary wrong: %q", s)
	}
	if s := SummarizePatchVerdict(patchVerdict{OK: false, Reason: "dup:a:add"}); s != "patch bad dup:a:add" {
		t.Fatalf("summary wrong: %q", s)
	}
}
