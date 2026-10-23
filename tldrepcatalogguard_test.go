package main

import "testing"

func TestTDCTldRiskHigh(t *testing.T) {
	for _, d := range []string{"xyz", "top", "tk", "gq", "icu", "zip"} {
		if TDCTldRisk(d) != TDCRiskHigh {
			t.Fatalf("%s must be high risk", d)
		}
	}
}

func TestTDCTldRiskCaseInsensitive(t *testing.T) {
	if TDCTldRisk("XYZ") != TDCRiskHigh {
		t.Fatal("uppercase XYZ high")
	}
	if TDCTldRisk("COM") != TDCRiskLow {
		t.Fatal("uppercase COM low")
	}
}

func TestTDCTldRiskCc(t *testing.T) {
	for _, d := range []string{"jp", "de", "fr", "uk", "br"} {
		if TDCTldRisk(d) != TDCRiskMedium {
			t.Fatalf("%s ccTLD medium", d)
		}
	}
}

func TestTDCTldRiskLow(t *testing.T) {
	for _, d := range []string{"com", "org", "net", "edu", "dev", "app"} {
		if TDCTldRisk(d) != TDCRiskLow {
			t.Fatalf("%s gTLD low", d)
		}
	}
}

func TestTDCTldRiskUnknown(t *testing.T) {
	if TDCTldRisk("zzz-not-a-tld") != "" {
		t.Fatal("unknown suffix empty")
	}
}

func TestTDCLastLabel(t *testing.T) {
	pairs := [][2]string{
		{"example.com", "com"},
		{"a.b.example.ORG", "org"},
		{"single", "single"},
		{"trailing.com.", "com"},
	}
	for _, p := range pairs {
		if got := TDCLastLabel(p[0]); got != p[1] {
			t.Fatalf("LastLabel(%q)=%q want %q", p[0], got, p[1])
		}
	}
}

func TestTDCAuditHighRiskFlagged(t *testing.T) {
	r := TDCAuditHost("cheap-deals.xyz")
	if !TDCHas(r, TDCReasonHighRiskSuffix) || r.Safe {
		t.Fatal("xyz host flagged high")
	}
}

func TestTDCAuditMainstreamSafe(t *testing.T) {
	r := TDCAuditHost("github.com")
	if !r.Safe || r.Risk != TDCRiskLow {
		t.Fatalf("github.com safe low, %v", r.Findings)
	}
}

func TestTDCAuditUnknownSuffix(t *testing.T) {
	r := TDCAuditHost("host.zzznotreal")
	if !TDCHas(r, TDCReasonUnknownSuffix) {
		t.Fatal("unknown suffix flagged")
	}
}

func TestTDCAuditLiteralIPv4(t *testing.T) {
	r := TDCAuditHost("192.168.1.1")
	if !TDCHas(r, TDCReasonIPAsDomain) || r.Safe {
		t.Fatal("literal ipv4 as domain flagged")
	}
}

func TestTDCAuditEmpty(t *testing.T) {
	r := TDCAuditHost("")
	if !TDCHas(r, TDCReasonEmptyHost) || r.Safe {
		t.Fatal("empty host unsafe")
	}
}

func TestTDCAuditLeadingDot(t *testing.T) {
	if !TDCHas(TDCAuditHost(".evil.com"), TDCReasonLeadingDot) {
		t.Fatal("leading dot")
	}
}

func TestTDCAuditTrailingDotAllowedButNoted(t *testing.T) {
	r := TDCAuditHost("example.com.")
	if !TDCHas(r, TDCReasonTrailingDot) {
		t.Fatal("FQDN trailing dot noted")
	}
}

func TestTDCAuditEmptyLabel(t *testing.T) {
	if !TDCHas(TDCAuditHost("a..com"), TDCReasonEmptyLabel) {
		t.Fatal("double dot empty label")
	}
}

func TestTDCAuditLabelTooLong(t *testing.T) {
	long := ""
	for i := 0; i < 64; i++ {
		long += "a"
	}
	r := TDCAuditHost(long + ".com")
	if !TDCHas(r, TDCReasonLabelTooLong) {
		t.Fatal("64-char label exceeds 63")
	}
}

func TestTDCAuditNameTooLong(t *testing.T) {
	label := ""
	for i := 0; i < 60; i++ {
		label += "a"
	}
	h := ""
	for i := 0; i < 5; i++ {
		if h != "" {
			h += "."
		}
		h += label
	}
	r := TDCAuditHost(h)
	if !TDCHas(r, TDCReasonNameTooLong) {
		t.Fatal("name > 253 flagged")
	}
}

func TestTDCAuditBadLabelChar(t *testing.T) {
	if !TDCHas(TDCAuditHost("exa mple.com"), TDCReasonBadLabelChar) {
		t.Fatal("space in label illegal")
	}
	if !TDCHas(TDCAuditHost("exa/mple.com"), TDCReasonBadLabelChar) {
		t.Fatal("slash in label illegal")
	}
}

func TestTDCAuditHyphenEdge(t *testing.T) {
	if !TDCHas(TDCAuditHost("-bad.com"), TDCReasonLabelHyphenEdge) {
		t.Fatal("leading hyphen")
	}
	if !TDCHas(TDCAuditHost("bad-.com"), TDCReasonLabelHyphenEdge) {
		t.Fatal("trailing hyphen")
	}
}

func TestTDCAuditNumericTld(t *testing.T) {
	r := TDCAuditHost("host.123")
	if !TDCHas(r, TDCReasonNumericTld) {
		t.Fatal("purely numeric tld flagged")
	}
}

func TestTDCSplitLabels(t *testing.T) {
	l := TDCSplitLabels("a.b.c")
	if len(l) != 3 || l[0] != "a" || l[2] != "c" {
		t.Fatal("split labels")
	}
}

func TestTDCLabelsAllNumeric(t *testing.T) {
	if !TDCLabelsAllNumeric([]string{"1", "2", "3", "4"}) {
		t.Fatal("all numeric")
	}
	if TDCLabelsAllNumeric([]string{"1", "2", "x", "4"}) {
		t.Fatal("not all numeric")
	}
	if TDCLabelsAllNumeric(nil) {
		t.Fatal("empty not all numeric")
	}
}

func TestTDCIsNumericLabel(t *testing.T) {
	if !TDCIsNumericLabel("12345") {
		t.Fatal("digits numeric")
	}
	if TDCIsNumericLabel("12a") || TDCIsNumericLabel("") {
		t.Fatal("mixed/empty not numeric")
	}
}
