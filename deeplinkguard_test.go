package main

import "testing"

func dlkTestConfig() DLKConfig {
	return DLKConfig{
		Scheme:       "qgl",
		AllowedHosts: map[string]bool{"cdn.example.com": true},
		Actions: map[string]DLKAllowedAction{
			"import": {
				Name:        "import",
				Params:      map[string]bool{"path": true, "source": true},
				IsPathParam: map[string]bool{"path": true},
				IsURLParam:  map[string]bool{"source": true},
			},
			"open": {
				Name:       "open",
				Params:     map[string]bool{"url": true},
				IsURLParam: map[string]bool{"url": true},
			},
		},
	}
}

func TestDLKValidImport(t *testing.T) {
	r := DLKParseAudit("qgl://import?path=mods%2Fabcd&source=https://cdn.example.com/x", dlkTestConfig())
	if !r.Safe {
		t.Fatalf("valid deeplink should be safe: %v", r.Findings)
	}
	if r.Action != "import" {
		t.Fatalf("action wrong %q", r.Action)
	}
}

func TestDLKUnknownAction(t *testing.T) {
	r := DLKParseAudit("qgl://run?cmd=calc", dlkTestConfig())
	if !r.HasReason(DLKReasonUnknownAction) {
		t.Fatalf("want unknown action: %v", r.Findings)
	}
}

func TestDLKMissingAction(t *testing.T) {
	r := DLKParseAudit("qgl://?x=1", dlkTestConfig())
	if !r.HasReason(DLKReasonMissingAction) {
		t.Fatalf("want missing action: %v", r.Findings)
	}
}

func TestDLKPathTraversal(t *testing.T) {
	r := DLKParseAudit("qgl://import?path=..%2F..%2FWindows%2Fwin.ini", dlkTestConfig())
	if !r.HasReason(DLKReasonPathTraversal) {
		t.Fatalf("want path traversal (percent encoded): %v", r.Findings)
	}
}

func TestDLKAbsolutePath(t *testing.T) {
	r := DLKParseAudit("qgl://import?path=C:%2FWindows", dlkTestConfig())
	if !r.HasReason(DLKReasonPathTraversal) {
		t.Fatalf("want absolute drive path: %v", r.Findings)
	}
}

func TestDLKUNCPath(t *testing.T) {
	r := DLKParseAudit(`qgl://import?path=%5C%5Cevil%5Cshare`, dlkTestConfig())
	if !r.HasReason(DLKReasonUNCTarget) {
		t.Fatalf("want unc path: %v", r.Findings)
	}
}

func TestDLKDangerousSchemeParam(t *testing.T) {
	r := DLKParseAudit("qgl://open?url=file:///C:/x", dlkTestConfig())
	if !r.HasReason(DLKReasonDangerousScheme) {
		t.Fatalf("want dangerous scheme: %v", r.Findings)
	}
}

func TestDLKOpenRedirect(t *testing.T) {
	r := DLKParseAudit("qgl://open?url=https://evil.example/x", dlkTestConfig())
	if !r.HasReason(DLKReasonOpenRedirect) {
		t.Fatalf("want open redirect: %v", r.Findings)
	}
}

func TestDLKControlChar(t *testing.T) {
	r := DLKParseAudit("qgl://import?path=ab%0acd", dlkTestConfig())
	if !r.HasReason(DLKReasonControlChar) {
		t.Fatalf("want control char: %v", r.Findings)
	}
}

func TestDLKSensitiveParam(t *testing.T) {
	r := DLKParseAudit("qgl://import?token=abc", dlkTestConfig())
	if !r.HasReason(DLKReasonSensitiveInParam) {
		t.Fatalf("want sensitive param: %v", r.Findings)
	}
}

func TestDLKUndeclaredParam(t *testing.T) {
	r := DLKParseAudit("qgl://open?url=https://cdn.example.com&extra=1", dlkTestConfig())
	if !r.HasReason(DLKReasonUnknownAction) {
		t.Fatalf("want undeclared param flagged: %v", r.Findings)
	}
}

func TestDLKTooLong(t *testing.T) {
	long := "qgl://open?url=" + string(make([]byte, 0))
	for i := 0; i < DLKMaxURLLen; i++ {
		long += "a"
	}
	r := DLKParseAudit(long, dlkTestConfig())
	if !r.HasReason(DLKReasonTooLong) {
		t.Fatalf("want too long: %v", r.Findings)
	}
}

func TestDLKForeignScheme(t *testing.T) {
	r := DLKParseAudit("other://open?x=1", dlkTestConfig())
	if r.Safe {
		t.Fatal("foreign scheme must not be parsed as safe")
	}
}

func TestDLKQueryDecoded(t *testing.T) {
	r := DLKParseAudit("qgl://import?path=mods%2Fabc&source=x", dlkTestConfig())
	if r.Params["path"] != "mods/abc" {
		t.Fatalf("query not percent decoded: %q", r.Params["path"])
	}
}

func TestDLKNormalOpenAllowedHost(t *testing.T) {
	r := DLKParseAudit("qgl://open?url=https://cdn.example.com/a", dlkTestConfig())
	if !r.Safe {
		t.Fatalf("open to allowed host should be safe: %v", r.Findings)
	}
}
