package main

import (
	"strings"
	"testing"
)

func importFindingsFor(t *testing.T, json string, roots []string) []ImportFinding {
	t.Helper()
	_, f, err := DecodeImportedConfig([]byte(json), roots, defaultImportConfigLimits())
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	return f
}

func hasFinding(findings []ImportFinding, field, reasonSubstr string) bool {
	for _, x := range findings {
		if x.Field == field && (reasonSubstr == "" || strings.Contains(x.Reason, reasonSubstr)) {
			return true
		}
	}
	return false
}

func TestImportCleanConfig(t *testing.T) {
	json := `{
		"javaPath":"C:\\Java\\bin\\java.exe",
		"gameDir":"C:\\Games\\mc",
		"versionId":"1.20.4-fabric",
		"memoryMb":4096,
		"downloadBaseUrl":"https://libraries.example.com/",
		"extraJvmArgs":["-XX:+UseG1GC"]
	}`
	f := importFindingsFor(t, json, []string{`C:\Games`})
	if HasRejectFindings(f) {
		t.Fatalf("clean config should have no reject findings, got %+v", f)
	}
}

func TestImportDuplicateKeyRejected(t *testing.T) {
	raw := []byte(`{"memoryMb":1024,"memoryMb":99999}`)
	if _, _, err := DecodeImportedConfig(raw, nil, defaultImportConfigLimits()); err == nil {
		t.Fatal("duplicate key must error")
	}
}

func TestImportUnknownFieldRejected(t *testing.T) {
	raw := []byte(`{"memoryMb":1024,"evil":1}`)
	if _, _, err := DecodeImportedConfig(raw, nil, defaultImportConfigLimits()); err == nil {
		t.Fatal("unknown field must error due to DisallowUnknownFields")
	}
}

func TestImportUncAndDevicePaths(t *testing.T) {
	// 原始字符串里 JSON 需要用四个反斜杠才能解码出 UNC 前缀两个反斜杠。
	uncJSON := `{"javaPath":"\\\\evil\\share\\java.exe"}`
	if f := importFindingsFor(t, uncJSON, nil); !hasFinding(f, "javaPath", "UNC") {
		t.Fatalf("UNC java path should be rejected: %+v", f)
	}
	if f := importFindingsFor(t, `{"gameDir":"C:\\Games\\CON"}`, []string{`C:\Games`}); !hasFinding(f, "gameDir", "设备名") {
		t.Fatalf("device name path should be rejected: %+v", f)
	}
	if f := importFindingsFor(t, `{"gameDir":"relative\\dir"}`, nil); !hasFinding(f, "gameDir", "绝对路径") {
		t.Fatalf("relative path should be rejected: %+v", f)
	}
}

func TestImportGameDirOutsideRoots(t *testing.T) {
	f := importFindingsFor(t, `{"gameDir":"D:\\Other\\mc"}`, []string{`C:\Games`})
	if !hasFinding(f, "gameDir", "根目录") {
		t.Fatalf("game dir outside roots should be rejected: %+v", f)
	}
}

func TestImportVersionIDTraversal(t *testing.T) {
	if f := importFindingsFor(t, `{"versionId":"../../evil"}`, nil); !hasFinding(f, "versionId", "穿越") {
		t.Fatalf("version traversal should reject: %+v", f)
	}
	if f := importFindingsFor(t, `{"versionId":"1.20/../../x"}`, nil); !hasFinding(f, "versionId", "分隔") {
		t.Fatalf("version separator should reject: %+v", f)
	}
}

func TestImportMemoryBounds(t *testing.T) {
	if f := importFindingsFor(t, `{"memoryMb":99999999}`, nil); !hasFinding(f, "memoryMb", "越界") {
		t.Fatalf("huge memory should reject: %+v", f)
	}
	if f := importFindingsFor(t, `{"memoryMb":16}`, nil); !hasFinding(f, "memoryMb", "越界") {
		t.Fatalf("tiny memory should reject: %+v", f)
	}
}

func TestImportURLRules(t *testing.T) {
	if f := importFindingsFor(t, `{"downloadBaseUrl":"http://mirror.example.com/x"}`, nil); !hasFinding(f, "downloadBaseUrl", "https") {
		t.Fatalf("http url should reject: %+v", f)
	}
	if f := importFindingsFor(t, `{"metaBaseUrl":"https://user:pass@host.example.com/x"}`, nil); !hasFinding(f, "metaBaseUrl", "userinfo") {
		t.Fatalf("userinfo url should reject: %+v", f)
	}
	if f := importFindingsFor(t, `{"authBaseUrl":"https://10.0.0.5/"}`, nil); !hasFinding(f, "authBaseUrl", "内网") {
		t.Fatalf("internal IP url should reject: %+v", f)
	}
	if f := importFindingsFor(t, `{"skinBaseUrl":"https://host.example.com:8443/"}`, nil); !hasFinding(f, "skinBaseUrl", "非标端口") {
		t.Fatalf("non-standard port should reject: %+v", f)
	}
}

func TestImportProxyRules(t *testing.T) {
	if f := importFindingsFor(t, `{"proxyUrl":"ftp://127.0.0.1:1080"}`, nil); !hasFinding(f, "proxyUrl", "协议") {
		t.Fatalf("bad proxy scheme should reject: %+v", f)
	}
	if f := importFindingsFor(t, `{"proxyUrl":"socks5://user:pw@127.0.0.1:1080"}`, nil); !hasFinding(f, "proxyUrl", "账号密码") {
		t.Fatalf("proxy creds should reject: %+v", f)
	}
	if f := importFindingsFor(t, `{"proxyUrl":"socks5://192.168.1.2:1080"}`, nil); !hasFinding(f, "proxyUrl", "回环") {
		t.Fatalf("non-loopback proxy IP should reject: %+v", f)
	}
	if f := importFindingsFor(t, `{"proxyUrl":"socks5://127.0.0.1:1080"}`, nil); HasRejectFindings(f) {
		t.Fatalf("loopback socks proxy should be allowed: %+v", f)
	}
}

func TestImportDangerousJVMArgs(t *testing.T) {
	cases := []string{
		`{"extraJvmArgs":["-javaagent:evil.jar"]}`,
		`{"extraJvmArgs":["-XX:OnError=calc.exe"]}`,
		`{"extraJvmArgs":["-Xverify:none"]}`,
		`{"extraJvmArgs":["-Djavax.net.ssl.trustStore=evil.jks"]}`,
	}
	for _, c := range cases {
		f := importFindingsFor(t, c, nil)
		if !hasFinding(f, "extraJvmArgs", "危险 JVM") {
			t.Fatalf("dangerous arg should reject for %s: %+v", c, f)
		}
	}
}

func TestImportServerPortAndHost(t *testing.T) {
	if f := importFindingsFor(t, `{"serverPort":70000}`, nil); !hasFinding(f, "serverPort", "端口") {
		t.Fatalf("bad port should reject: %+v", f)
	}
	if f := importFindingsFor(t, `{"serverHost":"a@b.com"}`, nil); !hasFinding(f, "serverHost", "userinfo") {
		t.Fatalf("userinfo host should reject: %+v", f)
	}
}

func TestImportSizeLimit(t *testing.T) {
	lim := defaultImportConfigLimits()
	big := make([]byte, lim.MaxBytes+1)
	for i := range big {
		big[i] = ' '
	}
	if _, _, err := DecodeImportedConfig(big, nil, lim); err == nil {
		t.Fatal("oversized config should error")
	}
}

func TestImportEmptyAndGarbage(t *testing.T) {
	if _, _, err := DecodeImportedConfig(nil, nil, defaultImportConfigLimits()); err == nil {
		t.Fatal("empty config should error")
	}
	if _, _, err := DecodeImportedConfig([]byte("not json"), nil, defaultImportConfigLimits()); err == nil {
		t.Fatal("garbage should error")
	}
}
