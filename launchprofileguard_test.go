package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAuditLaunchProfiles_OK(t *testing.T) {
	data := []byte(`{
	  "profiles": {
	    "abc": {"name":"生存","gameDir":"C:\\Games\\mc","lastVersionId":"1.20.4"},
	    "def": {"name":"模组","gameDir":"D:\\Games\\mcmods","javaDir":"C:\\Java\\jdk17","lastVersionId":"fabric-1.20.4"}
	  },
	  "settings": {}
	}`)
	v := auditLaunchProfiles(data, defaultLaunchProfileLimits())
	if !v.OK {
		t.Fatalf("合法 profiles 被拒绝: %+v", v.Findings)
	}
	if v.Name != "生存" || v.VersionID != "1.20.4" {
		t.Fatalf("主 profile 选择不符: %+v", v)
	}
	if !strings.Contains(v.GameDir, "Games") {
		t.Fatalf("gameDir 未归一: %q", v.GameDir)
	}
}

func TestAuditLaunchProfiles_TooBig(t *testing.T) {
	big := strings.Repeat(" ", 2<<20)
	v := auditLaunchProfiles([]byte(`{"profiles":{}}`+big), defaultLaunchProfileLimits())
	if v.OK {
		t.Fatal("超大文件应拒绝")
	}
	if !hasProfileFinding(v, "error", "$") {
		t.Fatalf("应有超限发现: %+v", v.Findings)
	}
}

func TestAuditLaunchProfiles_BadJSON(t *testing.T) {
	v := auditLaunchProfiles([]byte(`{not json`), defaultLaunchProfileLimits())
	if v.OK {
		t.Fatal("非法 JSON 应拒绝")
	}
}

func TestAuditLaunchProfiles_TooManyProfiles(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"profiles":{`)
	for i := 0; i < 600; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"p`)
		b.WriteString(fmt.Sprintf("%d", i))
		b.WriteString(`":{"name":"n","gameDir":"C:\\Games\\g","lastVersionId":"1.20"}}`)
	}
	b.WriteString(`}}`)
	v := auditLaunchProfiles([]byte(b.String()), defaultLaunchProfileLimits())
	if v.OK {
		t.Fatal("超量 profile 应拒绝")
	}
}

func TestAuditLaunchProfiles_DangerousGameDir(t *testing.T) {
	dir := "/etc"
	if runtime.GOOS == "windows" {
		dir = `C:\Windows\System32`
	}
	data := []byte(`{"profiles":{"a":{"name":"坏","gameDir":"` + dir + `","lastVersionId":"1.20"}}}`)
	v := auditLaunchProfiles(data, defaultLaunchProfileLimits())
	if v.OK {
		t.Fatal("危险 gameDir 应拒绝")
	}
	if !hasProfileFinding(v, "error", "$.profiles.a.gameDir") {
		t.Fatalf("应有 gameDir 越界发现: %+v", v.Findings)
	}
}

func TestAuditLaunchProfiles_RelativeGameDir(t *testing.T) {
	data := []byte(`{"profiles":{"a":{"name":"坏","gameDir":"relative/dir","lastVersionId":"1.20"}}}`)
	v := auditLaunchProfiles(data, defaultLaunchProfileLimits())
	if v.OK {
		t.Fatal("相对 gameDir 应拒绝")
	}
}

func TestAuditLaunchProfiles_ControlCharName(t *testing.T) {
	data := []byte("{\"profiles\":{\"a\":{\"name\":\"bad\x00name\",\"gameDir\":\"C:\\\\Games\\\\mc\",\"lastVersionId\":\"1.20\"}}}")
	v := auditLaunchProfiles(data, defaultLaunchProfileLimits())
	if v.OK {
		t.Fatal("控制字符名称应拒绝")
	}
}

func TestAuditLaunchProfiles_UNC(t *testing.T) {
	data := []byte(`{"profiles":{"a":{"name":"坏","gameDir":"\\\\server\\share\\mc","lastVersionId":"1.20"}}}`)
	v := auditLaunchProfiles(data, defaultLaunchProfileLimits())
	if v.OK {
		t.Fatal("UNC 路径应拒绝")
	}
}

func TestAuditLaunchProfiles_BadVersionID(t *testing.T) {
	data := []byte(`{"profiles":{"a":{"name":"好","gameDir":"C:\\Games\\mc","lastVersionId":"../escape"}}}`)
	v := auditLaunchProfiles(data, defaultLaunchProfileLimits())
	if v.OK {
		t.Fatal("穿越版本 ID 应拒绝")
	}
	if !hasProfileFinding(v, "error", "$.profiles.a.lastVersionId") {
		t.Fatalf("应有版本 ID 发现: %+v", v.Findings)
	}
}

func TestAuditLaunchProfiles_TypeMismatchSkipped(t *testing.T) {
	data := []byte(`{"profiles":{"a":{"name":123,"gameDir":"C:\\Games\\mc"}}}`)
	v := auditLaunchProfiles(data, defaultLaunchProfileLimits())
	if v.OK || v.ProfileID != "" {
		t.Fatalf("类型不符应跳过并最终无可用 profile: %+v", v)
	}
	if !hasProfileFinding(v, "error", "$") {
		t.Fatalf("应报无可用的 profile: %+v", v.Findings)
	}
}

func TestAuditLaunchProfiles_MainProfileDeterministic(t *testing.T) {
	// 字典序最小 id 应被选为主 profile（a 先于 z）。
	data := []byte(`{
	  "profiles": {
	    "z": {"name":"后","gameDir":"C:\\Games\\z","lastVersionId":"1.20"},
	    "a": {"name":"前","gameDir":"C:\\Games\\a","lastVersionId":"1.19"}
	  }
	}`)
	v := auditLaunchProfiles(data, defaultLaunchProfileLimits())
	if v.ProfileID != "a" || v.Name != "前" {
		t.Fatalf("主 profile 选择不确定: %+v", v)
	}
}

func TestSanitizeProfilePath_Empty(t *testing.T) {
	_, f := sanitizeProfilePath("", defaultLaunchProfileLimits())
	if f == nil || f.Severity != "error" {
		t.Fatal("空路径应报错")
	}
}

func TestSanitizeProfilePath_TooLong(t *testing.T) {
	l := defaultLaunchProfileLimits()
	l.PathRunes = 16
	_, f := sanitizeProfilePath(strings.Repeat("a", 40), l)
	if f == nil || !strings.Contains(f.Reason, "上限") {
		t.Fatal("超长路径应报错")
	}
}

func TestSanitizeVersionID_EmptyWarn(t *testing.T) {
	_, f := sanitizeVersionID("  ", defaultLaunchProfileLimits())
	if f == nil || f.Severity != "warn" {
		t.Fatalf("空版本 ID 应为 warn: %+v", f)
	}
}

func TestProfileVerdictSummary(t *testing.T) {
	data := []byte(`{"profiles":{"a":{"name":"好","gameDir":"C:\\Games\\mc","lastVersionId":"1.20"}}}`)
	v := auditLaunchProfiles(data, defaultLaunchProfileLimits())
	s := profileVerdictSummary(v)
	if !strings.Contains(s, "可用") {
		t.Fatalf("summary 不符: %s", s)
	}
}

func TestAuditLaunchProfiles_FileBacked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "launcher_profiles.json")
	// 用一个平台无关的安全绝对目录（t.TempDir() 本身就是安全绝对路径）。
	gameDir := filepath.Join(dir, "mc")
	if err := os.MkdirAll(gameDir, 0755); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"profiles":{"a":{"name":"文件","gameDir":"` + gameDir + `","lastVersionId":"1.20.4"}}}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v := auditLaunchProfiles(raw, defaultLaunchProfileLimits())
	if !v.OK {
		t.Fatalf("文件回灌应通过: %+v", v.Findings)
	}
}

func hasProfileFinding(v LaunchProfileVerdict, sev, path string) bool {
	for _, it := range v.Findings {
		if it.Severity == sev && it.Path == path {
			return true
		}
	}
	return false
}
