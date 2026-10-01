package main

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestSplitEnvironEntry(t *testing.T) {
	cases := []struct {
		in       string
		key      string
		value    string
		ok       bool
	}{
		{"PATH=C:\\Windows;C:\\Java", "PATH", "C:\\Windows;C:\\Java", true},
		{"EMPTY=", "EMPTY", "", true},
		{"A=B=C=D", "A", "B=C=D", true},
		{"NOEQUALS", "", "", false},
	}
	for _, c := range cases {
		key, value, ok := splitEnvironEntry(c.in)
		if ok != c.ok || key != c.key || value != c.value {
			t.Fatalf("splitEnvironEntry(%q) = (%q,%q,%v), want (%q,%q,%v)", c.in, key, value, ok, c.key, c.value, c.ok)
		}
	}
}

func TestIsJVMInjectionEnv(t *testing.T) {
	blocked := []string{
		"JAVA_TOOL_OPTIONS",
		"java_tool_options", // Windows 大小写不敏感
		"_Java_Options",
		"JDK_JAVA_OPTIONS",
		"_jpi_vm_options",
		"IBM_JAVA_OPTIONS",
		"classpath",
		"CLASSPATH",
	}
	for _, k := range blocked {
		if !isJVMInjectionEnv(k) {
			t.Errorf("期望 %q 命中 JVM 注入变量黑名单", k)
		}
	}
	safe := []string{"PATH", "APPDATA", "SystemRoot", "TEMP", "USERPROFILE", "JAVA_HOME"}
	for _, k := range safe {
		if isJVMInjectionEnv(k) {
			t.Errorf("%q 不应被当成 JVM 注入变量", k)
		}
	}
}

func envMap(entries []string) map[string]string {
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		k, v, ok := splitEnvironEntry(e)
		if ok {
			m[strings.ToUpper(k)] = v
		}
	}
	return m
}

func TestBuildGameEnvironmentStripsInjectionVars(t *testing.T) {
	parent := []string{
		"SystemRoot=C:\\Windows",
		"PATH=C:\\Java\\bin",
		"APPDATA=C:\\Users\\t\\AppData\\Roaming",
		"JAVA_TOOL_OPTIONS=-javaagent:C:\\evil.jar",
		"_JAVA_OPTIONS=-agentpath:bad.dll",
		"JDK_JAVA_OPTIONS=-Xmx9999m",
		"CLASSPATH=C:\\malicious-classes",
	}
	var stripped []string
	env := buildGameEnvironment(parent, nil, &stripped)
	m := envMap(env)

	for _, wantGone := range []string{"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"} {
		if _, exists := m[wantGone]; exists {
			t.Errorf("黑名单变量 %s 应被剥掉，实际环境: %v", wantGone, env)
		}
	}
	for k, want := range map[string]string{
		"SYSTEMROOT": "C:\\Windows",
		"PATH":       "C:\\Java\\bin",
		"APPDATA":    "C:\\Users\\t\\AppData\\Roaming",
	} {
		if got := m[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	gotStripped := append([]string(nil), stripped...)
	sort.Strings(gotStripped)
	wantStripped := []string{"_JAVA_OPTIONS", "CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS"}
	if !reflect.DeepEqual(gotStripped, wantStripped) {
		t.Fatalf("stripped = %v, want %v", gotStripped, wantStripped)
	}
}

func TestBuildGameEnvironmentExtraOverrides(t *testing.T) {
	parent := []string{
		"PATH=C:\\old",
		"TEMP=C:\\tmp",
		"JAVA_TOOL_OPTIONS=-javaagent:x", // 即使在 extra 里也不许带进来
	}
	extra := map[string]string{
		"PATH":    "C:\\new;C:\\old",
		"JAVA_HOME": "C:\\jdk",
	}
	var stripped []string
	env := buildGameEnvironment(parent, extra, &stripped)
	m := envMap(env)

	if m["PATH"] != "C:\\new;C:\\old" {
		t.Fatalf("extra 中的 PATH 应覆盖父环境，实际 %q", m["PATH"])
	}
	if m["JAVA_HOME"] != "C:\\jdk" {
		t.Fatalf("extra 新增变量缺失，实际 %v", env)
	}
	if m["TEMP"] != "C:\\tmp" {
		t.Fatalf("未提及的变量应原样透传")
	}
	if _, exists := m["JAVA_TOOL_OPTIONS"]; exists {
		t.Fatal("黑名单变量不应出现在最终环境里")
	}
}

func TestBuildGameEnvironmentDedupAndGarbage(t *testing.T) {
	parent := []string{
		"PATH=C:\\first",
		"PATH=C:\\second",         // 重复键，后值覆盖
		"BROKEN_LINE",             // 非 K=V，丢弃
		"=C:=C:\\current-dir",     // Windows drive-cwd 条目，键为空，丢弃
		"",                        // 空条目
		"JAVA_TOOL_OPTIONS=bad",   // 命中黑名单
		"lower=kept",
	}
	var stripped []string
	env := buildGameEnvironment(parent, nil, &stripped)
	m := envMap(env)

	if m["PATH"] != "C:\\second" {
		t.Fatalf("重复变量应保留最后一个值，实际 %q", m["PATH"])
	}
	if _, exists := m[""]; exists {
		t.Fatal("空键条目不应保留")
	}
	if m["LOWER"] != "kept" {
		t.Fatalf("普通变量应原样保留，实际 %v", env)
	}
	if len(stripped) != 1 || stripped[0] != "JAVA_TOOL_OPTIONS" {
		t.Fatalf("stripped = %v", stripped)
	}
}

func TestCurrentGameEnvironmentReturnsUsableEnv(t *testing.T) {
	env, stripped := currentGameEnvironment(nil)
	if len(env) == 0 {
		t.Fatal("净化后的环境不应为空：系统变量必须透传")
	}
	for _, e := range env {
		key, _, ok := splitEnvironEntry(e)
		if !ok {
			t.Fatalf("返回了非法环境条目: %q", e)
		}
		if isJVMInjectionEnv(key) {
			t.Fatalf("净化后仍含黑名单变量: %s", key)
		}
	}
	// 本机即使没设这些变量，stripped 也必须是已初始化的切片（可能长度为 0）。
	if stripped == nil {
		t.Fatal("stripped 不应为 nil，便于调用方直接 range 记日志")
	}
}
