package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeJoinAllowsInside(t *testing.T) {
	base := t.TempDir()
	got, err := safeJoin(base, filepath.Join("mods", "fabric.jar"))
	if err != nil {
		t.Fatalf("safeJoin inside path: %v", err)
	}
	absBase, _ := filepath.Abs(base)
	if !strings.HasPrefix(got, absBase+string(os.PathSeparator)) {
		t.Fatalf("joined path %q not under base %q", got, absBase)
	}
}

// 任何 .. 段都必须被拒绝，不能写出 base 目录。
func TestSafeJoinRejectsParentTraversal(t *testing.T) {
	base := t.TempDir()
	for _, rel := range []string{
		filepath.Join("..", "escape.jar"),
		filepath.Join("mods", "..", "..", "escape.jar"),
		".." + string(os.PathSeparator) + "escape.jar",
	} {
		if _, err := safeJoin(base, rel); err == nil {
			t.Errorf("safeJoin(%q) 应拒绝路径遍历", rel)
		}
	}
}

// 含 NUL 字节的条目名必须被拒绝（防 C 字符串截断类问题）。
func TestSafeJoinRejectsNulByte(t *testing.T) {
	base := t.TempDir()
	if _, err := safeJoin(base, "evil\x00.jar"); err == nil {
		t.Fatal("safeJoin 必须拒绝含 NUL 字节的路径")
	}
}

func TestHasPathTraversalChars(t *testing.T) {
	if !hasPathTraversalChars("../x") {
		t.Error("../x 应判定为含遍历字符")
	}
	if !hasPathTraversalChars("a\x00b") {
		t.Error("含 NUL 字节应判定为含遍历字符")
	}
	if hasPathTraversalChars(filepath.Join("mods", "normal.jar")) {
		t.Error("普通相对路径不应误判为遍历")
	}
}
