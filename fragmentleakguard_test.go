package main

import "testing"

func TestFRNoFragment(t *testing.T) {
	base, fs := FRAuditRequest("https://api.example.com/v1")
	if base != "https://api.example.com/v1" || len(fs) != 0 {
		t.Fatalf("url without fragment should be clean: %q %v", base, fs)
	}
}

func TestFRFragmentInRequest(t *testing.T) {
	base, fs := FRAuditRequest("https://api.example.com/v1#section")
	if base != "https://api.example.com/v1" {
		t.Fatalf("base should strip fragment %q", base)
	}
	has := false
	for _, f := range fs {
		if f.Reason == FRReasonFragmentInRequestTarget {
			has = true
		}
	}
	if !has {
		t.Fatalf("want fragment in request target: %v", fs)
	}
}

func TestFRAccessTokenFragment(t *testing.T) {
	_, fs := FRAuditRequest("https://app.example.com/cb#access_token=abc123&state=z")
	sens := false
	for _, f := range fs {
		if f.Reason == FRReasonSensitiveFragment {
			sens = true
		}
	}
	if !sens {
		t.Fatalf("want sensitive fragment: %v", fs)
	}
}

func TestFRIdTokenFragment(t *testing.T) {
	_, fs := FRAuditRequest("https://app/#id_token=xyz")
	sens := false
	for _, f := range fs {
		if f.Reason == FRReasonSensitiveFragment {
			sens = true
		}
	}
	if !sens {
		t.Fatalf("want id_token sensitive: %v", fs)
	}
}

func TestFRControlCharFragment(t *testing.T) {
	_, fs := FRAuditRequest("https://app/#a\x0db")
	ctrl := false
	for _, f := range fs {
		if f.Reason == FRReasonFragmentControlChar {
			ctrl = true
		}
	}
	if !ctrl {
		t.Fatalf("want control char: %v", fs)
	}
}

func TestFRLogStripped(t *testing.T) {
	safe, fs := FRAuditLog("https://api.example.com/x#token=secret")
	if safe != "https://api.example.com/x" {
		t.Fatalf("log url should strip fragment %q", safe)
	}
	found := false
	for _, f := range fs {
		if f.Reason == FRReasonFragmentToLog {
			found = true
		}
	}
	if !found {
		t.Fatalf("want fragment-to-log finding: %v", fs)
	}
}

func TestFRLogClean(t *testing.T) {
	safe, fs := FRAuditLog("https://api.example.com/x")
	if safe != "https://api.example.com/x" || len(fs) != 0 {
		t.Fatalf("clean log url should stay: %q %v", safe, fs)
	}
}

func TestFRCrossOriginKept(t *testing.T) {
	fs := FRAuditNavigation("app.example.com", "evil.example.com",
		"https://evil.example.com/#access_token=abc")
	kept := false
	for _, f := range fs {
		if f.Reason == FRReasonFragmentKeptCrossOrigin {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("want cross-origin fragment retention: %v", fs)
	}
}

func TestFRSameOriginFragmentOK(t *testing.T) {
	fs := FRAuditNavigation("app.example.com", "app.example.com",
		"https://app.example.com/page#section")
	for _, f := range fs {
		if f.Reason == FRReasonFragmentKeptCrossOrigin {
			t.Fatalf("same origin fragment should not flag cross-origin: %v", fs)
		}
	}
}

func TestFRPercentEncodedSensitiveKey(t *testing.T) {
	// access_token 的键被百分号编码，仍应识别
	_, fs := FRAuditRequest("https://app/#%61ccess_token=abc")
	sens := false
	for _, f := range fs {
		if f.Reason == FRReasonSensitiveFragment {
			sens = true
		}
	}
	if !sens {
		t.Fatalf("want percent-encoded sensitive key detected: %v", fs)
	}
}

func TestFRSplitOnlyFirstHash(t *testing.T) {
	sp := FRSplit("https://a/p#x#y")
	if !sp.HasFrag || sp.Base != "https://a/p" || sp.Fragment != "x#y" {
		t.Fatalf("split should only split first hash: %+v", sp)
	}
}
