package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathWithinRootLexical(t *testing.T) {
	root := filepath.Clean("/tmp/game/libraries")
	cases := []struct {
		child string
		want  bool
	}{
		{filepath.Join(root, "a.jar"), true},
		{filepath.Join(root, "com", "x", "y.jar"), true},
		{root, true},
		{filepath.Join(root, "..", "..", "etc", "passwd"), false},
		{filepath.Clean("/tmp/game/librariesX"), false}, // 兄弟目录前缀
		{filepath.Join(root, "..", "libraries2", "a.jar"), false},
	}
	for _, c := range cases {
		if got := PathWithinRoot(c.child, root); got != c.want {
			t.Errorf("PathWithinRoot(%q) = %v, want %v", c.child, got, c.want)
		}
	}
}

func TestPathWithinRootRejectsBadInput(t *testing.T) {
	if PathWithinRoot("a\x00b", "/tmp/game") {
		t.Error("NUL 字节路径必须被拒绝")
	}
	if PathWithinRoot("", "/tmp/game") {
		t.Error("空路径必须被拒绝")
	}
}

func TestPathWithinRootRelativeResolvedToAbs(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "natives")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(mustGetwd(t), filepath.Join(sub, "x.dll"))
	if err != nil {
		t.Fatal(err)
	}
	if !PathWithinRoot(rel, root) {
		t.Errorf("相对路径解析后应在 root 内: %q", rel)
	}
}

func TestResolvedPathWithinRootRealTree(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "bin")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(inner, "java.exe")
	if err := os.WriteFile(target, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := ResolvedPathWithinRoot(target, root); !ok {
		t.Error("真实位于 root 内的文件应通过")
	}
	if _, ok := ResolvedPathWithinRoot(target, filepath.Join(root, "other")); ok {
		t.Error("不存在的 root 应判定不通过")
	}
}

func TestResolvedPathWithinRootSymlinkEscape(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "evil.exe"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, "java.exe")
	if err := os.Symlink(filepath.Join(outside, "evil.exe"), link); err != nil {
		t.Skip("当前环境不允许创建符号链接，跳过：" + err.Error())
	}
	if _, ok := ResolvedPathWithinRoot(link, root); ok {
		t.Error("符号链接解析后逃出 root，必须判定不通过")
	}
}

func TestResolvedPathWithinRootNonexistentChild(t *testing.T) {
	root := t.TempDir()
	// child 尚不存在，但父目录真实在 root 内：应通过。
	future := filepath.Join(root, "newdir", "a.jar")
	if _, ok := ResolvedPathWithinRoot(future, root); !ok {
		t.Error("root 内尚不存在的目标应允许（父目录真实在 root 内/词法在 root 内）")
	}
	// 词法逃逸的不存在目标应拒绝。
	esc := filepath.Join(root, "..", "..", "outside.jar")
	if _, ok := ResolvedPathWithinRoot(esc, root); ok {
		t.Error("词法逃逸的不存在目标必须拒绝")
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}
