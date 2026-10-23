package main

import "testing"

func usmHas(fs []USMFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestUSMHTTPSDownload(t *testing.T) {
	safe, sc, _ := USMCheck("https://cdn.test/m.jar", USMUsageDownload)
	if !safe || sc != "https" {
		t.Fatalf("https download should pass sc=%q", sc)
	}
}

func TestUSMHTTPDownload(t *testing.T) {
	_, _, fs := USMCheck("http://cdn.test/m.jar", USMUsageDownload)
	if !usmHas(fs, USMReasonCleartextDownload) {
		t.Fatalf("want cleartext download, got %v", fs)
	}
}

func TestUSMHTTPExternalLink(t *testing.T) {
	safe, _, _ := USMCheck("http://site.test/page", USMUsageExternalLink)
	if !safe {
		t.Fatal("http external link allowed (confirm handled elsewhere)")
	}
}

func TestUSMFile(t *testing.T) {
	_, _, fs := USMCheck("file:///etc/passwd", USMUsageFetchJSON)
	if !usmHas(fs, USMReasonFileScheme) {
		t.Fatalf("want file scheme, got %v", fs)
	}
}

func TestUSMData(t *testing.T) {
	_, _, fs := USMCheck("data:application/java-archive;base64,AAAA", USMUsageDownload)
	if !usmHas(fs, USMReasonDataScheme) {
		t.Fatalf("want data scheme, got %v", fs)
	}
}

func TestUSMJS(t *testing.T) {
	_, _, fs := USMCheck("javascript:alert(1)", USMUsageExternalLink)
	if !usmHas(fs, USMReasonScriptScheme) {
		t.Fatalf("want script scheme, got %v", fs)
	}
}

func TestUSMJar(t *testing.T) {
	_, _, fs := USMCheck("jar:https://x.test/a.jar!/x.class", USMUsageFetchJSON)
	if !usmHas(fs, USMReasonInternalScheme) {
		t.Fatalf("want jar internal, got %v", fs)
	}
}

func TestUSMFTP(t *testing.T) {
	_, _, fs := USMCheck("ftp://files.test/a.jar", USMUsageDownload)
	if !usmHas(fs, USMReasonInternalScheme) {
		t.Fatalf("want ftp internal, got %v", fs)
	}
}

func TestUSMCustomLaunch(t *testing.T) {
	_, _, fs := USMCheck("minecraft://connect/host", USMUsageExternalLink)
	if !usmHas(fs, USMReasonCustomLaunchScheme) {
		t.Fatalf("want launch scheme, got %v", fs)
	}
}

func TestUSMMsLaunch(t *testing.T) {
	_, _, fs := USMCheck("ms-settings:windowsupdate", USMUsageExternalLink)
	if !usmHas(fs, USMReasonCustomLaunchScheme) {
		t.Fatalf("want ms- launch, got %v", fs)
	}
}

func TestUSMMissing(t *testing.T) {
	_, _, fs := USMCheck("not-a-url", USMUsageFetchJSON)
	if !usmHas(fs, USMReasonSchemeMissing) {
		t.Fatalf("want missing scheme, got %v", fs)
	}
}

func TestUSMUnknown(t *testing.T) {
	_, sc, fs := USMCheck("weirdproto://x", USMUsageFetchJSON)
	if sc != "weirdproto" || !usmHas(fs, USMReasonSchemeNotAllowed) {
		t.Fatalf("want unknown not allowed, sc=%q fs=%v", sc, fs)
	}
}

func TestUSMSchemeUpper(t *testing.T) {
	_, sc, _ := USMCheck("HTTPS://x.test/a", USMUsageDownload)
	if sc != "https" {
		t.Fatalf("scheme not folded: %q", sc)
	}
}
