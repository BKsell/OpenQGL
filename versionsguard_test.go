package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateVersionJSON(t *testing.T) {
	lim := defaultVersionJSONLimits()

	good := &VersionJSON{
		ID:           "1.20.1",
		Jar:          "versions/1.20.1/1.20.1.jar",
		InheritsFrom: "",
		Libraries: []Library{
			{Name: "net.minecraft:client:1.20.1",
				Downloads: &LibDownloads{Artifact: &LibArtifact{Path: "libraries/net/minecraft/client/1.20.1/client-1.20.1.jar"}}},
		},
		Downloads: &VersionDownloads{Client: &LibArtifact{Path: "versions/1.20.1/1.20.1.jar"}},
		AssetIndex: &AssetIndexRef{ID: "1.20"},
	}
	if vd := ValidateVersionJSON(good, "1.20.1", lim); !vd.OK {
		t.Fatalf("good rejected: %s", vd.Reason)
	}

	bad := []struct {
		name  string
		json  *VersionJSON
		dirID string
		want  string
	}{
		{"dotdot-jar", &VersionJSON{ID: "1.20.1", Jar: "versions/1.20.1/../../../evil.jar"}, "1.20.1", "jar:dotdot-segment"},
		{"absolute-jar", &VersionJSON{ID: "1.20.1", Jar: "C:/evil.jar"}, "1.20.1", "jar:absolute-path"},
		{"backslash", &VersionJSON{ID: "1.20.1", Jar: "versions\\1.20.1\\a.jar"}, "1.20.1", "jar:backslash-path"},
		{"outside-prefix", &VersionJSON{ID: "1.20.1", Jar: "libraries/a/b.jar"}, "1.20.1", "jar:outside-prefix"},
		{"id-mismatch", &VersionJSON{ID: "1.20.2", Jar: "versions/1.20.2/1.20.2.jar"}, "1.20.1", "id-mismatch-dir"},
		{"id-separator", &VersionJSON{ID: "a/b", Jar: ""}, "a/b", "id:id-separator"},
		{"inherit-self", &VersionJSON{ID: "x", InheritsFrom: "x"}, "x", "inherits-self"},
		{"lib-path-dotdot", &VersionJSON{ID: "x",
			Libraries: []Library{{Name: "a:b:1", Downloads: &LibDownloads{Artifact: &LibArtifact{Path: "libraries/../../e.jar"}}}}}, "x", "lib-artifact:dotdot-segment:0"},
		{"lib-name-parts", &VersionJSON{ID: "x", Libraries: []Library{{Name: "a:b"}}}, "x", "lib-name:name-parts:0"},
		{"natives-dotdot", &VersionJSON{ID: "x", Libraries: []Library{{Name: "a:b:1", Natives: map[string]string{"windows": "../n"}}}}, "x", "natives:dotdot-segment:windows"},
		{"downloads-dotdot", &VersionJSON{ID: "x", Downloads: &VersionDownloads{Client: &LibArtifact{Path: "versions/x/../y.jar"}}}, "x", "downloads:client:dotdot-segment"},
		{"asset-separator", &VersionJSON{ID: "x", AssetIndex: &AssetIndexRef{ID: "a/b"}}, "x", "asset-index:id-separator"},
	}
	for _, c := range bad {
		if vd := ValidateVersionJSON(c.json, c.dirID, lim); vd.OK || vd.Reason != c.want {
			t.Fatalf("%s: got ok=%v reason=%q want %q", c.name, vd.OK, vd.Reason, c.want)
		}
	}
}

func TestCheckInheritChain(t *testing.T) {
	lim := defaultVersionJSONLimits()
	known := map[string]bool{"a": true, "b": true, "c": true}
	// 静态链：a -> b -> c，c 无父
	parents := map[string]string{"a": "b", "b": "c"}
	orig := readVersionJSONForChain
	defer func() { readVersionJSONForChain = orig }()
	readVersionJSONForChain = func(id string) (*VersionJSON, error) {
		if p, ok := parents[id]; ok {
			return &VersionJSON{ID: id, InheritsFrom: p}, nil
		}
		return &VersionJSON{ID: id}, nil
	}
	if vd := CheckInheritChain("a", func(id string) bool { return known[id] }, lim); !vd.OK {
		t.Fatalf("valid chain rejected: %s", vd.Reason)
	}
	// 环：a -> b -> a
	parents["a"] = "b"
	parents["b"] = "a"
	if vd := CheckInheritChain("a", func(id string) bool { return known[id] }, lim); vd.OK {
		t.Fatalf("cycle accepted")
	}
	// 缺失：a -> missing
	parents["a"] = "missing"
	if vd := CheckInheritChain("a", func(id string) bool { return known[id] }, lim); vd.OK {
		t.Fatalf("missing parent accepted")
	}
}

func TestCheckVersionsDir(t *testing.T) {
	lim := defaultVersionJSONLimits()
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	goodJSON := `{"id":"1.20.1","jar":"versions/1.20.1/1.20.1.jar","libraries":[]}`
	badJSON := `{"id":"1.20.1","jar":"versions/1.20.1/../../evil.jar"}`
	write("1.20.1/1.20.1.json", goodJSON)
	write("bad/bad.json", badJSON)
	write("nested/not-a-version.json", `{}`)

	bad := CheckVersionsDir(root, lim)
	if len(bad) != 1 {
		t.Fatalf("expected 1 bad entry, got %v", bad)
	}
	if bad[0] != "bad:jar:dotdot-segment" {
		t.Fatalf("unexpected bad entry: %v", bad)
	}
}

func TestSummarizeVersionVerdict(t *testing.T) {
	if s := SummarizeVersionVerdict(nil); s != "versions-guard clean" {
		t.Fatalf("clean summary wrong: %q", s)
	}
	s := SummarizeVersionVerdict([]string{"x:jar:dotdot-segment"})
	if s != "versions-guard bad=1 first=x:jar:dotdot-segment" {
		t.Fatalf("summary wrong: %q", s)
	}
}

// ensure json import used in tests via roundtrip helper
func TestVersionJSONRoundtrip(t *testing.T) {
	var v VersionJSON
	if err := json.Unmarshal([]byte(`{"id":"1.20.1","jar":"versions/1.20.1/1.20.1.jar"}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.ID != "1.20.1" || v.Jar != "versions/1.20.1/1.20.1.jar" {
		t.Fatalf("roundtrip wrong: %+v", v)
	}
}
