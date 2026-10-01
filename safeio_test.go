package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSecureWritePrivateFileHappy(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "secret.json")
	payload := []byte(`{"token":"abc","n":1}`)

	if err := secureWritePrivateFile(target, payload); err != nil {
		t.Fatalf("secureWritePrivateFile 失败: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("内容不一致: %q != %q", got, payload)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("Lstat 失败: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("落盘目标不应是符号链接")
	}
	if !info.Mode().IsRegular() {
		t.Fatal("落盘目标必须是普通文件")
	}
	// 权限严格检查只在类 Unix 上有意义；Windows 的 chmod 只影响只读位。
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Fatalf("敏感文件权限应为 0600，实际 %o", perm)
		}
		dInfo, _ := os.Stat(filepath.Dir(target))
		if dInfo.Mode().Perm() != 0700 {
			t.Fatalf("敏感目录权限应为 0700，实际 %o", dInfo.Mode().Perm())
		}
	}

	// 同目录不应残留 .safeio-* 临时文件。
	entries, _ := os.ReadDir(filepath.Dir(target))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".safeio-") {
			t.Fatalf("发现未清理的临时文件: %s", e.Name())
		}
	}

	// 覆盖写：第二次写不同内容，读回应为新内容，且始终只有一个目标文件。
	payload2 := []byte(`{"token":"xyz"}`)
	if err := secureWritePrivateFile(target, payload2); err != nil {
		t.Fatalf("覆盖写失败: %v", err)
	}
	got2, _ := os.ReadFile(target)
	if string(got2) != string(payload2) {
		t.Fatalf("覆盖后内容不一致: %q", got2)
	}
}

func TestSecureWriteRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "password.json")
	if err := os.Symlink(outside, link); err != nil {
		// Windows 默认无创建符号链接权限（需开发者模式 / 管理员），不能把环境
		// 缺失误判成代码缺陷；Linux/macOS 上创建失败则是真问题。
		if runtime.GOOS == "windows" {
			t.Skip("当前 Windows 环境无创建符号链接权限，跳过符号链接写穿用例")
		}
		t.Fatal(err)
	}

	err := secureWritePrivateFile(link, []byte("PWNED"))
	if err == nil {
		t.Fatal("向符号链接写入必须被拒绝")
	}
	got, _ := os.ReadFile(outside)
	if string(got) != "original" {
		t.Fatalf("符号链接目标被写穿！内容变成 %q", got)
	}
}

func TestWritePrivateJSONRoundtrip(t *testing.T) {
	type cred struct {
		User string `json:"user"`
		Tag  []int  `json:"tag"`
	}
	path := filepath.Join(t.TempDir(), "deep", "c.json")
	want := cred{User: "bk", Tag: []int{1, 2, 3}}
	if err := writePrivateJSON(path, want); err != nil {
		t.Fatalf("writePrivateJSON 失败: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got cred
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("写回的不是合法 JSON: %v", err)
	}
	if got.User != want.User || len(got.Tag) != 3 || got.Tag[2] != 3 {
		t.Fatalf("JSON 往返不一致: %+v", got)
	}
}

func TestCopyFileSecureLimit(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	payload := []byte("0123456789ABCDEF") // 16 字节
	if err := os.WriteFile(src, payload, 0600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out", "dst.bin")

	if err := copyFileSecure(src, dst, 0600, 16); err != nil {
		t.Fatalf("恰好等于上限应当允许: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != string(payload) {
		t.Fatalf("复制内容不一致: %q", got)
	}

	dst2 := filepath.Join(dir, "out2", "dst.bin")
	err := copyFileSecure(src, dst2, 0600, 15)
	if err == nil {
		t.Fatal("超过上限一个字节也必须拒绝")
	}
	if _, statErr := os.Stat(dst2); !os.IsNotExist(statErr) {
		t.Fatal("超限时不应留下目标文件")
	}
}

func TestEnsurePrivateDirIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "c")
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatalf("对已存在目录重复执行不应报错: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("应当创建为目录")
	}
}

func TestIsSymlinkOrSpecial(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope")
	if bad, err := isSymlinkOrSpecial(missing); err != nil || bad {
		t.Fatalf("不存在的路径应返回 (false,nil)，实际 (%v,%v)", bad, err)
	}
	regular := filepath.Join(dir, "f")
	if err := os.WriteFile(regular, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if bad, _ := isSymlinkOrSpecial(regular); bad {
		t.Fatal("普通文件不应被判为特殊文件")
	}
}
