package main

import "testing"

func TestCNExactMatch(t *testing.T) {
	ok, valid := CNMatchName("api.example.com", "api.example.com")
	if !ok || !valid {
		t.Fatal("exact DNS name should match")
	}
	if ok, _ := CNMatchName("api.example.com", "api.example.com."); !ok {
		t.Fatal("trailing-dot FQDN should normalize and match")
	}
}

func TestCNBareSuffixNoMatch(t *testing.T) {
	ok, _ := CNMatchName("example.com", "notexample.com")
	if ok {
		t.Fatal("bare substring suffix must not match")
	}
}

func TestCNWildcardSingleLabel(t *testing.T) {
	ok, valid := CNMatchName("*.example.com", "a.example.com")
	if !ok || !valid {
		t.Fatal("*.example.com should match one label")
	}
}

func TestCNWildcardNotAcrossDot(t *testing.T) {
	ok, _ := CNMatchName("*.example.com", "a.b.example.com")
	if ok {
		t.Fatal("*.example.com must not match two labels deep")
	}
}

func TestCNPartialWildcardInvalid(t *testing.T) {
	ok, valid := CNMatchName("good*.com", "goodx.com")
	if ok || valid {
		t.Fatal("partial-label wildcard must be invalid")
	}
	ok, valid = CNMatchName("a.*.com", "a.b.com")
	if ok || valid {
		t.Fatal("mid-name wildcard must be invalid")
	}
}

func TestCNWildcardSuffixTrick(t *testing.T) {
	ok, _ := CNMatchName("*.com", "evil.com")
	if ok {
		t.Fatal("*.com is too broad / malformed and must not match")
	}
}

func TestCNEvaluateNoMatch(t *testing.T) {
	_, fs := CNEvaluate([]string{"api.example.com"}, nil, "other.example.com", false)
	if !CNHasReason(fs, CNReasonNoNameMatched) {
		t.Fatalf("no SAN matches server name must flag: %v", fs)
	}
}

func TestCNEvaluateIP(t *testing.T) {
	if safe, _ := CNEvaluate(nil, []string{"52.1.2.3"}, "52.1.2.3", true); !safe {
		t.Fatal("matching IP SAN should pass")
	}
	_, fs := CNEvaluate([]string{"52.1.2.3"}, nil, "52.1.2.3", true)
	if !CNHasReason(fs, CNReasonIPWithoutIPSAN) {
		t.Fatalf("IP server needs IP SAN, DNS name insufficient: %v", fs)
	}
}

func TestCNEvaluateWildcardOK(t *testing.T) {
	safe, fs := CNEvaluate([]string{"*.example.com"}, nil, "cdn.example.com", false)
	if !safe {
		t.Fatalf("wildcard SAN single-label should be safe: %v", fs)
	}
}
