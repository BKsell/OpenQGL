package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestHasPathTraversalChars 锁定路径遍历探测的判定边界。
// 只要出现 ".." 或 NUL 字节就视为可疑（宁可误杀文件名里带两点的普通文件，
// 也不放过任何可能跳出解压目录的条目）。
func TestHasPathTraversalChars(t *testing.T) {
	bad := []string{
		"../escape",
		"../../etc/passwd",
		"foo/../../bar",
		"a/..",
		"..",
		"normal\x00.txt",
	}
	for _, p := range bad {
		if !hasPathTraversalChars(p) {
			t.Errorf("%q 应被判为含遍历字符", p)
		}
	}
	good := []string{
		"mods/sodium.jar",
		"config/mod.json",
		"overrides/a/b/c.txt",
		"./plain",
	}
	for _, p := range good {
		if hasPathTraversalChars(p) {
			t.Errorf("%q 不应被判为含遍历字符", p)
		}
	}
}

// TestSafeJoinAllowsNested 正常的多层相对路径必须落在 base 目录内。
func TestSafeJoinAllowsNested(t *testing.T) {
	base := t.TempDir()
	cases := []string{
		"mods",
		"mods/sodium-fabric.jar",
		"config/sodium/options.json",
		filepath.Join("a", "b", "c.txt"),
	}
	for _, rel := range cases {
		got, err := safeJoin(base, rel)
		if err != nil {
			t.Fatalf("合法路径 %q 被拒绝: %v", rel, err)
		}
		abs, _ := filepath.Abs(got)
		absBase, _ := filepath.Abs(base)
		if !strings.HasPrefix(abs, absBase+string(filepath.Separator)) {
			t.Fatalf("%q 解析结果 %s 跳出了 base %s", rel, abs, absBase)
		}
	}
}

// TestSafeJoinBlocksTraversal 各种越界写法必须全部被拦下。
func TestSafeJoinBlocksTraversal(t *testing.T) {
	base := t.TempDir()
	attacks := []string{
		"../evil.txt",
		"../../evil.txt",
		"mods/../../evil.txt",
		"mods/../../../windows/system32/cmd.exe",
		"a/b/../../../../escape",
		"..",
	}
	for _, rel := range attacks {
		if _, err := safeJoin(base, rel); err == nil {
			t.Errorf("路径遍历 %q 必须返回错误", rel)
		}
	}
}

// TestSafeJoinBlocksNull NUL 字节注入（在 C 层会截断路径）必须被拒绝。
func TestSafeJoinBlocksNull(t *testing.T) {
	base := t.TempDir()
	if _, err := safeJoin(base, "safe\x00/../../evil"); err == nil {
		t.Fatal("含 NUL 字节的路径必须被拒绝")
	}
}

// TestSafeJoinCannotReachSibling 验证无法借 ".." 落到 base 的兄弟目录。
func TestSafeJoinCannotReachSibling(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "game")
	sibling := filepath.Join(parent, "SECRET")
	rel, err := filepath.Rel(base, filepath.Join(sibling, "loot.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := safeJoin(base, rel); err == nil {
		t.Fatalf("通过相对路径 %q 访问兄弟目录必须被拒绝", rel)
	}
}
