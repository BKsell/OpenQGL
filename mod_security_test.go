package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsPathInDir(t *testing.T) {
	root := t.TempDir()

	innerFile := filepath.Join(root, "mods", "fabric-api.jar")
	if err := os.MkdirAll(filepath.Dir(innerFile), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(innerFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"root itself", root, true},
		{"nested file", innerFile, true},
		{"nested dir", filepath.Join(root, "mods"), true},
		{"dot segment still inside", filepath.Join(root, "mods", "..", "mods", "a.jar"), true},
		{"parent escape", filepath.Join(root, "..", "evil.jar"), false},
		{"deep parent escape", filepath.Join(root, "mods", "..", "..", "evil.jar"), false},
		{"sibling dir", filepath.Join(filepath.Dir(root), "sibling", "x.jar"), false},
		{"unrelated temp dir", filepath.Join(t.TempDir(), "x.jar"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isPathInDir(c.path, root); got != c.want {
				t.Errorf("isPathInDir(%q)=%v want %v", c.path, got, c.want)
			}
		})
	}
}

// 目录内合法的、仅名字以两个点开头的条目（"..foo"）不应被误判为越界，
// 同时真正的 ".." 父级跳转必须被拦住。
func TestIsPathInDirDotDotBoundary(t *testing.T) {
	root := t.TempDir()
	dotName := filepath.Join(root, "..keep_my_mods")
	if err := os.MkdirAll(filepath.Join(dotName, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir ..keep: %v", err)
	}
	if !isPathInDir(filepath.Join(dotName, "a.jar"), root) {
		t.Error("legitimate '..keep_my_mods' entry wrongly reported outside root")
	}
	if isPathInDir(filepath.Join(root, "..keep_my_mods", "..", "..", "evil.jar"), root) {
		t.Error("escape through parent segments should be rejected")
	}
}

func TestIsValidModID(t *testing.T) {
	valid := []string{"a", "fabric-api", "sodium_1.20", "A-Z_0-9", strings.Repeat("a", 100)}
	for _, id := range valid {
		if !isValidModID(id) {
			t.Errorf("expected valid mod id: %q", id)
		}
	}
	invalid := []string{
		"",
		"../escape",
		"a/b",
		"a.b",
		"has space",
		"a;rm",
		"中文",
		strings.Repeat("a", 101),
	}
	for _, id := range invalid {
		if isValidModID(id) {
			t.Errorf("expected invalid mod id: %q", id)
		}
	}
}

func TestIsValidMCVersion(t *testing.T) {
	valid := []string{"1.20.1", "1_20-1", "1-20_1"}
	for _, v := range valid {
		if !isValidMCVersion(v) {
			t.Errorf("expected valid mc version: %q", v)
		}
	}
	invalid := []string{"1.20.1;rm -rf", "v1.20", "1.20 1", "中", strings.Repeat("1", 21)}
	for _, v := range invalid {
		if isValidMCVersion(v) {
			t.Errorf("expected invalid mc version: %q", v)
		}
	}
}
