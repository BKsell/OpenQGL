package main

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseOptionsTextBasic(t *testing.T) {
	text := "# comment line\nversion:3120\nfov:70\nfullscreen:true\n"
	r := parseOptionsText(text)
	if !r.OK {
		t.Fatalf("expected OK, got issues: %v", r.Issues)
	}
	if r.Options["version"] != "3120" || r.Options["fov"] != "70" || r.Options["fullscreen"] != "true" {
		t.Fatalf("unexpected options: %v", r.Options)
	}
}

func TestParseOptionsTextBoolConverge(t *testing.T) {
	text := "autoJump:yes\nfullscreen:1\nsnooperEnabled:off\n"
	r := parseOptionsText(text)
	if !r.OK {
		t.Fatalf("expected OK: %v", r.Issues)
	}
	if r.Options["autoJump"] != "true" || r.Options["fullscreen"] != "true" || r.Options["snooperEnabled"] != "false" {
		t.Fatalf("bool converge failed: %v", r.Options)
	}
	warn := 0
	for _, it := range r.Issues {
		if it.Severity == "warn" {
			warn++
		}
	}
	if warn == 0 {
		t.Fatalf("expected warn issues for converge")
	}
}

func TestParseOptionsRejectCRLFInjection(t *testing.T) {
	// 值内塞 \r 伪造新配置行（真实攻击是行内 \r；CRLF 行尾是合法容忍项）：
	// "lastServer:x\rfov:999" 会把 fov 塞进同一个值。
	text := "version:3120\nlastServer:x\rfov:999\n"
	r := parseOptionsText(text)
	if r.OK {
		t.Fatalf("CRLF inside value must be rejected, options=%v", r.Options)
	}
}

func TestParseOptionsRejectControlChar(t *testing.T) {
	text := "version:3120\nfov:7\x000\n"
	r := parseOptionsText(text)
	if r.OK {
		t.Fatalf("NUL control char must be rejected")
	}
}

func TestParseOptionsRejectBadKey(t *testing.T) {
	for _, bad := range []string{"evil key:1", "has space:x", "key;x:1", ":emptykey"} {
		r := parseOptionsText("version:3120\n" + bad + "\n")
		if r.OK {
			t.Fatalf("bad key %q must be rejected", bad)
		}
	}
	// 值里的冒号是合法的（lastServer 就是 host:port）。
	r := parseOptionsText("version:3120\nlastServer:mc.example.com:25565\n")
	if !r.OK {
		t.Fatalf("colon in value must be accepted: %v", r.Issues)
	}
}

func TestParseOptionsRejectNoColon(t *testing.T) {
	r := parseOptionsText("version:3120\nthis line has no colon\n")
	if r.OK {
		t.Fatalf("line without colon must be rejected")
	}
}

func TestParseOptionsFileTooLarge(t *testing.T) {
	big := strings.Repeat("a", maxOptionsFileBytes+1)
	r := parseOptionsText(big)
	if r.OK {
		t.Fatalf("oversize file must be rejected")
	}
}

func TestParseOptionsLineTooLong(t *testing.T) {
	line := "version:" + strings.Repeat("9", maxOptionLineBytes)
	r := parseOptionsText(line + "\n")
	if r.OK {
		t.Fatalf("oversize line must be rejected")
	}
}

func TestParseOptionsCountLimit(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < maxOptionsCount+5; i++ {
		sb.WriteString("key")
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString(":1\n")
	}
	r := parseOptionsText(sb.String())
	if r.OK {
		t.Fatalf("too many keys must be rejected")
	}
}

func TestParseOptionsCRLFLineEndingTolerated(t *testing.T) {
	// 行尾 \r（CRLF 文件）允许：TrimSuffix 剥离。
	text := "version:3120\r\nfov:70\r\n"
	r := parseOptionsText(text)
	if !r.OK {
		t.Fatalf("CRLF line endings should be tolerated: %v", r.Issues)
	}
	if r.Options["version"] != "3120" || r.Options["fov"] != "70" {
		t.Fatalf("unexpected: %v", r.Options)
	}
}

func TestSerializeOptionsRoundTrip(t *testing.T) {
	text := "version:3120\nfov:70\nfullscreen:yes\n"
	r := parseOptionsText(text)
	if !r.OK {
		t.Fatalf("parse failed: %v", r.Issues)
	}
	out, issues := serializeOptions(r.Options)
	if len(issues) != 0 {
		t.Fatalf("serialize issues: %v", issues)
	}
	r2 := parseOptionsText(out)
	if !r2.OK {
		t.Fatalf("round-trip parse failed: %v", r2.Issues)
	}
	// 布尔值被收敛为 true。
	if r2.Options["fullscreen"] != "true" {
		t.Fatalf("round-trip bool not converged: %v", r2.Options)
	}
	if r2.Options["version"] != "3120" {
		t.Fatalf("round-trip value changed: %v", r2.Options)
	}
}

func TestSerializeOptionsDropsUnsafeValue(t *testing.T) {
	r := parseOptionsText("version:3120\n")
	if !r.OK {
		t.Fatalf("parse failed")
	}
	r.Options["injected"] = "a\r\nfov:999"
	_, issues := serializeOptions(r.Options)
	found := false
	for _, it := range issues {
		if it.Key == "injected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unsafe value must be dropped with issue, issues=%v", issues)
	}
	// 非法键被静默跳过。
	r.Options["bad key"] = "1"
	out, issues2 := serializeOptions(r.Options)
	if strings.Contains(out, "bad key") {
		t.Fatalf("bad key leaked into serialized output")
	}
	_ = issues2
}

func TestAuditOptionsText(t *testing.T) {
	parsed, issues := auditOptionsText("version:3120\nfov:70\n")
	if !parsed.OK {
		t.Fatalf("audit parse failed: %v", issues)
	}
	bad, badIssues := auditOptionsText("version:3120\nlastServer:x\r\nfov:7\x000\n")
	if bad.OK {
		t.Fatalf("audit must flag unsafe input")
	}
	_ = badIssues
}

func TestKnownBooleanConvergeTable(t *testing.T) {
	cases := map[string]string{
		"true":  "true",
		"TRUE":  "true",
		"yes":   "true",
		"1":     "true",
		"on":    "true",
		"false": "false",
		"no":    "false",
		"0":     "false",
		"off":   "false",
	}
	for in, want := range cases {
		if got := normalizeBoolValue(in); got != want {
			t.Fatalf("normalizeBoolValue(%q)=%q want %q", in, got, want)
		}
	}
}
