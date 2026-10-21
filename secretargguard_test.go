package main

import "testing"

func TestSecretArgInlineSwitch(t *testing.T) {
	argv := []string{"java", "-jar", "mc.jar", "--accessToken=abc123secretvalue"}
	f := AuditSecretArgs(argv, nil)
	if len(f) == 0 {
		t.Fatal("inline access token must be flagged")
	}
	if f[0].Category != secretCategoryToken {
		t.Fatalf("category=%s", f[0].Category)
	}
}

func TestSecretArgSeparateValue(t *testing.T) {
	argv := []string{"java", "--accessToken", "XYZTOKENVALUE", "--username", "player"}
	f := AuditSecretArgs(argv, nil)
	found := false
	for _, x := range f {
		if x.Arg == "XYZTOKENVALUE" && x.Category == secretCategoryToken {
			found = true
		}
	}
	if !found {
		t.Fatalf("separate token value must be flagged: %+v", f)
	}
}

func TestSecretArgPasswordAndProperty(t *testing.T) {
	cases := [][]string{
		{"java", "--password=p@ss"},
		{"java", "-Dlogin.password=hunter2"},
		{"java", "-Dhttps.proxyPassword=pw"},
	}
	for _, argv := range cases {
		if f := AuditSecretArgs(argv, nil); len(f) == 0 {
			t.Fatalf("expected secret finding for %v", argv)
		}
	}
}

func TestSecretArgJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	argv := []string{"java", jwt}
	f := AuditSecretArgs(argv, nil)
	if len(f) != 1 || f[0].Category != secretCategoryJWT {
		t.Fatalf("jwt should be classified, got %+v", f)
	}
}

func TestSecretArgLongHex(t *testing.T) {
	hex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	f := AuditSecretArgs([]string{"java", hex}, nil)
	if len(f) != 1 || f[0].Category != secretCategoryHex {
		t.Fatalf("long hex should be flagged: %+v", f)
	}
}

func TestSecretArgBearer(t *testing.T) {
	f := AuditSecretArgs([]string{"helper", "--header", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"}, nil)
	if len(f) == 0 {
		t.Fatal("bearer token must be flagged")
	}
	if f[0].Category != secretCategoryBearer {
		t.Fatalf("category=%s", f[0].Category)
	}
}

func TestSecretArgBenignArgsPass(t *testing.T) {
	argv := []string{
		"java", "-Xmx4G", "-XX:+UseG1GC",
		"--username", "Steve",
		"--version", "1.20.4",
		"--gameDir", `C:\Games\mc`,
		"-Djava.library.path=natives",
	}
	f := AuditSecretArgs(argv, nil)
	if len(f) != 0 {
		t.Fatalf("benign argv must pass: %+v", f)
	}
}

func TestSecretArgAllowListedPlaceholder(t *testing.T) {
	argv := []string{"java", "--accessToken", "@stdin:token"}
	allow := map[string]struct{}{"@stdin:token": {}}
	if f := AuditSecretArgs(argv, allow); len(f) != 0 {
		t.Fatalf("explicitly allowed handle must pass: %+v", f)
	}
}

func TestSecretArgSafeAndError(t *testing.T) {
	if ok, _ := SecretArgsSafe([]string{"java", "-Xmx2G"}, nil); !ok {
		t.Fatal("benign should be safe")
	}
	if ok, f := SecretArgsSafe([]string{"java", "--password=x"}, nil); ok {
		t.Fatal("password should not be safe")
	} else if SecretArgError(f) == nil {
		t.Fatal("error should be non-nil when findings exist")
	}
	if SecretArgError(nil) != nil {
		t.Fatal("nil findings should yield nil error")
	}
}

func TestSecretArgPlaceholder(t *testing.T) {
	p := PlaceholderForSecret("token", 7)
	if p != "@secret:token:7" {
		t.Fatalf("placeholder=%s", p)
	}
}

func TestSecretArgRedactForLog(t *testing.T) {
	argv := []string{"java", "--accessToken=SECRETVALUE", "-Xmx4G"}
	out := RedactArgvForLog(argv)
	if out[1] != "[REDACTED]" {
		t.Fatalf("arg not redacted: %q", out[1])
	}
	if out[0] != "java" || out[2] != "-Xmx4G" {
		t.Fatalf("benign args changed: %+v", out)
	}
	// 原 argv 不被修改。
	if argv[1] == "[REDACTED]" {
		t.Fatal("RedactArgvForLog must not mutate input")
	}
}

func TestSecretArgShortHexNotFlagged(t *testing.T) {
	// 短十六进制（如 16 位）不达阈值，避免误伤普通数字参数。
	f := AuditSecretArgs([]string{"java", "--pid", "0123456789abcdef"}, nil)
	// --pid 不是敏感开关，值也不够长，应放行。
	for _, x := range f {
		if x.Category == secretCategoryHex {
			t.Fatalf("short hex should not be flagged: %+v", f)
		}
	}
}
