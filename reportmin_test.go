package main

import (
	"strings"
	"testing"
)

// reportmin_test.go —— 遥测最小化内核的穷举测试：值去敏（路径 / 令牌 / 长十六
// 进制 / 换行注入）、字段白名单、长度与预算上界、JSON 递归最小化。

func TestScrubLocalPaths(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"C:\\Users\\bob\\mods\\evil.jar", "<本地路径:evil.jar>"},
		{"c:/users/bob/mods/evil.jar", "<本地路径:evil.jar>"},
		{"/home/bob/mods/evil.jar", "<本地路径:evil.jar>"},
		{"\\\\server\\share\\x", "<本地路径:x>"},
		{"相对路径/不掩码.jar", "相对路径/不掩码.jar"},
		{"/usr", "/usr"}, // 单段根路径不掩码
		{"值: D:\\data\\x.txt 结尾", "值: <本地路径:x.txt> 结尾"},
	}
	for _, tc := range cases {
		got := ScrubTelemetryValue(tc.in)
		if got != tc.want {
			t.Fatalf("ScrubTelemetryValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestScrubTokens(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://user:pass@example.com/x", "https://[redacted]example.com/x"},
		{"token=abc123&next=1", "token=[redacted]next=1"},
		{"?access_token=SECRET&x=1", "?access_token=[redacted]x=1"},
		{"key=abcdef&sign=deadbeef", "key=[redacted]sign=[redacted]"},
		{"plain text no tokens", "plain text no tokens"},
	}
	for _, tc := range cases {
		got := ScrubTelemetryValue(tc.in)
		if got != tc.want {
			t.Fatalf("ScrubTelemetryValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMaskLongHex(t *testing.T) {
	long := strings.Repeat("a1b2c3d4e5", 5) // 50 位十六进制
	got := ScrubTelemetryValue(long)
	if strings.Contains(got, "a1b2") {
		t.Fatalf("long hex not masked: %q", got)
	}
	if !strings.Contains(got, "<hex") {
		t.Fatalf("mask marker missing: %q", got)
	}
	// 短串（如版本号）不误伤。
	short := "1a2b3c"
	if got := ScrubTelemetryValue(short); got != short {
		t.Fatalf("short hex wrongly masked: %q", got)
	}
}

func TestScrubControlChars(t *testing.T) {
	in := "line1\r\nline2\x00\x1b[31m"
	got := ScrubTelemetryValue(in)
	if strings.Contains(got, "\r") || strings.Contains(got, "\n") {
		t.Fatalf("newline not folded: %q", got)
	}
	if strings.Contains(got, "\x00") || strings.Contains(got, "\x1b") || strings.Contains(got, "[31m") {
		t.Fatalf("control/terminal residue: %q", got)
	}
	if got != "line1 line2" {
		t.Fatalf("content damaged: %q", got)
	}
}

func TestMinimizeMap(t *testing.T) {
	in := map[string]string{
		"eventId":   "e-1",
		"detail":    "C:\\Users\\bob\\x.txt",
		"secretEnv": "SHOULD_DROP",
	}
	out, dropped := MinimizeMap(in)
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	if _, ok := out["secretEnv"]; ok {
		t.Fatal("non-whitelisted field leaked")
	}
	if !strings.Contains(out["detail"], "<本地路径:x.txt>") {
		t.Fatalf("detail not scrubbed: %q", out["detail"])
	}
}

func TestMinimizeJSON(t *testing.T) {
	obj := map[string]interface{}{
		"version": "1.0",
		"detail":  "C:\\Users\\bob\\mods\\a.jar 下载失败 token=abc",
		"added": []interface{}{
			map[string]interface{}{"name": "x.jar", "dir": "D:\\data\\mods"},
			map[string]interface{}{"name": "y.jar", "dir": "mods"},
		},
		"internalState": "DROP_ME",
	}
	data, dropped, err := MinimizeJSON(obj)
	if err != nil {
		t.Fatalf("MinimizeJSON error: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	s := string(data)
	if strings.Contains(s, "DROP_ME") {
		t.Fatalf("non-whitelisted field leaked: %s", s)
	}
	if strings.Contains(s, "token=abc") {
		t.Fatalf("token value leaked: %s", s)
	}
	if !strings.Contains(s, "token=[redacted]") {
		t.Fatalf("token not redacted: %s", s)
	}
	if strings.Contains(s, "C:\\Users") {
		t.Fatalf("absolute path leaked: %s", s)
	}
	if !strings.Contains(s, "\"version\":\"1.0\"") {
		t.Fatalf("whitelisted field missing: %s", s)
	}
}

func TestMinimizeJSONBudgets(t *testing.T) {
	// 数组条数预算：500 之外截断。
	big := make([]interface{}, 600)
	for i := range big {
		big[i] = map[string]interface{}{"name": "f" + strings.Repeat("x", 10)}
	}
	obj := map[string]interface{}{"added": big}
	data, _, err := MinimizeJSON(obj)
	if err != nil {
		t.Fatalf("MinimizeJSON error: %v", err)
	}
	if strings.Count(string(data), "\"name\"") > 500 {
		t.Fatalf("array not capped: %d name fields", strings.Count(string(data), "\"name\""))
	}
	// 深度预算：嵌套超过 MaxDepth 折叠。
	deep := map[string]interface{}{"detail": "x"}
	for i := 0; i < 12; i++ {
		deep = map[string]interface{}{"added": []interface{}{deep}}
	}
	obj = map[string]interface{}{"added": deep}
	data, _, err = MinimizeJSON(obj)
	if err != nil {
		t.Fatalf("deep MinimizeJSON error: %v", err)
	}
	if strings.Contains(string(data), "深度超限") == false && len(data) > 2000 {
		t.Fatalf("depth budget not enforced: %d bytes", len(data))
	}
}
