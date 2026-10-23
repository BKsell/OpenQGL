package main

import (
	"strings"
	"testing"
)

func TestCBPlainServer(t *testing.T) {
	r := CBAudit("play.example.com", CBFieldServerAddress)
	if !r.Safe {
		t.Fatalf("plain server should be safe: %v", r.Findings)
	}
}

func TestCBJVMFlagPastedIntoServer(t *testing.T) {
	r := CBAudit("-javaagent:evil.jar", CBFieldServerAddress)
	if !r.HasReason(CBReasonJVMFlagInjection) {
		t.Fatalf("want jvm flag injection: %v", r.Findings)
	}
}

func TestCBJVMFlagAllowedInArgsBox(t *testing.T) {
	// JVM 参数框允许 -Xmx，但 -javaagent 仍属危险（flag 表含 -javaagent）
	r := CBAudit("-Xmx4G", CBFieldJVMArgs)
	if r.HasReason(CBReasonJVMFlagInjection) {
		t.Fatalf("-Xmx is not in injection list: %v", r.Findings)
	}
}

func TestCBMultiLine(t *testing.T) {
	r := CBAudit("play.example.com\n-Xmx4G", CBFieldServerAddress)
	if !r.HasReason(CBReasonNewline) {
		t.Fatalf("want multiline: %v", r.Findings)
	}
}

func TestCBControlChar(t *testing.T) {
	r := CBAudit("ab\x00cd", CBFieldGenericURL)
	if !r.HasReason(CBReasonControlChar) {
		t.Fatalf("want control char: %v", r.Findings)
	}
}

func TestCBFileScheme(t *testing.T) {
	r := CBAudit("file:///C:/Windows/win.ini", CBFieldGenericURL)
	if !r.HasReason(CBReasonDangerousScheme) {
		t.Fatalf("want file scheme: %v", r.Findings)
	}
}

func TestCBJavascriptScheme(t *testing.T) {
	r := CBAudit("javascript:alert(1)", CBFieldGenericURL)
	if !r.HasReason(CBReasonDangerousScheme) {
		t.Fatalf("want javascript scheme: %v", r.Findings)
	}
}

func TestCBUNCBackslash(t *testing.T) {
	r := CBAudit(`\\evil\share\x`, CBFieldServerAddress)
	if !r.HasReason(CBReasonUNCPath) {
		t.Fatalf("want backslash UNC: %v", r.Findings)
	}
}

func TestCBProtocolRelativeUNC(t *testing.T) {
	r := CBAudit("//evil/share", CBFieldServerAddress)
	if !r.HasReason(CBReasonUNCPath) {
		t.Fatalf("want protocol-relative UNC: %v", r.Findings)
	}
}

func TestCBNormalHTTPSNotUNC(t *testing.T) {
	r := CBAudit("https://example.com/path", CBFieldServerAddress)
	if r.HasReason(CBReasonUNCPath) {
		t.Fatalf("normal https wrongly flagged UNC: %v", r.Findings)
	}
}

func TestCBEmbeddedCredentials(t *testing.T) {
	r := CBAudit("https://user:p4ss@evil.example.com/", CBFieldServerAddress)
	if !r.HasReason(CBReasonEmbeddedCreds) {
		t.Fatalf("want embedded creds: %v", r.Findings)
	}
}

func TestCBNoCredsUserinfoNoPassword(t *testing.T) {
	// 仅 user@host（无冒号密码）不应判内嵌密码
	r := CBAudit("https://user@example.com/", CBFieldServerAddress)
	if r.HasReason(CBReasonEmbeddedCreds) {
		t.Fatalf("userinfo without password wrongly flagged: %v", r.Findings)
	}
}

func TestCBAppLauncher(t *testing.T) {
	r := CBAudit("ms-msdt:id=x", CBFieldGenericURL)
	if !r.HasReason(CBReasonAppLauncher) {
		t.Fatalf("want app launcher protocol: %v", r.Findings)
	}
}

func TestCBHTMLSmuggling(t *testing.T) {
	r := CBAudit("<script>x</script>", CBFieldInstanceName)
	if !r.HasReason(CBReasonHTMLSmuggling) {
		t.Fatalf("want html smuggling: %v", r.Findings)
	}
}

func TestCBTooLong(t *testing.T) {
	r := CBAudit(strings.Repeat("a", CBMaxPasteBytes+1), CBFieldGenericURL)
	if !r.HasReason(CBReasonTooLong) {
		t.Fatalf("want too long: %v", r.Findings)
	}
}

func TestCBTrimWhitespace(t *testing.T) {
	r := CBAudit("  play.example.com  ", CBFieldServerAddress)
	if !r.HasReason(CBReasonLeadingTrailSpace) {
		t.Fatalf("want surrounding whitespace: %v", r.Findings)
	}
	if r.Sanitized != "play.example.com" {
		t.Fatalf("sanitized wrong %q", r.Sanitized)
	}
}

func TestCBSanitizedStripsControl(t *testing.T) {
	r := CBAudit("ab\x01cd", CBFieldInstanceName)
	if r.Sanitized != "abcd" {
		t.Fatalf("sanitized should strip control %q", r.Sanitized)
	}
}

func TestCBDataURIScheme(t *testing.T) {
	r := CBAudit("data:text/html,<b>", CBFieldGenericURL)
	if !r.HasReason(CBReasonDangerousScheme) {
		t.Fatalf("want data scheme: %v", r.Findings)
	}
}
