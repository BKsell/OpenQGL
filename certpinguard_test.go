package main

import "testing"

// 合法的标准 base64（44 字符，sha256/32 字节）
const spnpValidPin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
const spnpValidPin2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

func TestSPNPHealthyRuleSet(t *testing.T) {
	rules := []SPNPHostRule{{
		Host: "api.minecraftservices.com",
		Pins: []SPNPPin{{"sha256", spnpValidPin}, {"sha256", spnpValidPin2}},
	}}
	r := SPNPValidateRules(rules, 1_000_000)
	if !r.Safe {
		t.Fatalf("healthy rule set should pass: %v", r.Findings)
	}
}

func TestSPNPEmptyPinSet(t *testing.T) {
	rules := []SPNPHostRule{{Host: "a.example", Pins: nil}}
	r := SPNPValidateRules(rules, 1_000_000)
	if !r.HasReason(SPNPReasonEmptyPinSet) {
		t.Fatalf("want empty pin set: %v", r.Findings)
	}
}

func TestSPNPSinglePinNoBackup(t *testing.T) {
	rules := []SPNPHostRule{{Host: "a.example", Pins: []SPNPPin{{"sha256", spnpValidPin}}}}
	r := SPNPValidateRules(rules, 1_000_000)
	if !r.HasReason(SPNPReasonNoBackupPin) {
		t.Fatalf("want no backup pin: %v", r.Findings)
	}
}

func TestSPNPWeakAlgorithm(t *testing.T) {
	rules := []SPNPHostRule{{Host: "a.example", Pins: []SPNPPin{
		{"sha1", spnpValidPin}, {"sha256", spnpValidPin2}}}}
	r := SPNPValidateRules(rules, 1_000_000)
	if !r.HasReason(SPNPReasonWeakPinAlgorithm) {
		t.Fatalf("want weak algorithm: %v", r.Findings)
	}
}

func TestSPNPMalformedBase64(t *testing.T) {
	rules := []SPNPHostRule{{Host: "a.example", Pins: []SPNPPin{
		{"sha256", "not base64!!!"}, {"sha256", spnpValidPin2}}}}
	r := SPNPValidateRules(rules, 1_000_000)
	if !r.HasReason(SPNPReasonMalformedPin) {
		t.Fatalf("want malformed pin: %v", r.Findings)
	}
}

func TestSPNPUrlSafeBase64Rejected(t *testing.T) {
	bad := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-="
	rules := []SPNPHostRule{{Host: "a.example", Pins: []SPNPPin{
		{"sha256", bad}, {"sha256", spnpValidPin2}}}}
	r := SPNPValidateRules(rules, 1_000_000)
	if !r.HasReason(SPNPReasonMalformedPin) {
		t.Fatalf("want url-safe pin rejected: %v", r.Findings)
	}
}

func TestSPNPSubdomainMatch(t *testing.T) {
	rules := []SPNPHostRule{{
		Host: "example.com", IncludeSub: true,
		Pins: []SPNPPin{{"sha256", spnpValidPin}, {"sha256", spnpValidPin2}}}}
	r := SPNPMatch(rules, "api.example.com", spnpValidPin, true)
	if !r.Safe {
		t.Fatalf("subdomain should match pin: %v", r.Findings)
	}
}

func TestSPNPExactMatch(t *testing.T) {
	rules := []SPNPHostRule{{
		Host: "api.example.com",
		Pins: []SPNPPin{{"sha256", spnpValidPin}, {"sha256", spnpValidPin2}}}}
	if r := SPNPMatch(rules, "api.example.com", spnpValidPin2, true); !r.Safe {
		t.Fatal("exact host backup pin should match")
	}
}

func TestSPNPNoPinMatchFailClosed(t *testing.T) {
	rules := []SPNPHostRule{{
		Host: "api.example.com",
		Pins: []SPNPPin{{"sha256", spnpValidPin}, {"sha256", spnpValidPin2}}}}
	r := SPNPMatch(rules, "api.example.com", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=", true)
	if r.Safe || !r.HasReason(SPNPReasonNoHostMatch) {
		t.Fatalf("want pin mismatch fail closed: %v", r.Findings)
	}
}

func TestSPNPUnknownHostFailClosed(t *testing.T) {
	rules := []SPNPHostRule{{Host: "a.example", Pins: []SPNPPin{
		{"sha256", spnpValidPin}, {"sha256", spnpValidPin2}}}}
	if r := SPNPMatch(rules, "evil.example", spnpValidPin, true); r.Safe {
		t.Fatal("unknown host must fail closed")
	}
}

func TestSPNPUnknownHostFailOpen(t *testing.T) {
	rules := []SPNPHostRule{{Host: "a.example", Pins: []SPNPPin{
		{"sha256", spnpValidPin}, {"sha256", spnpValidPin2}}}}
	if r := SPNPMatch(rules, "other.example", spnpValidPin, false); !r.Safe {
		t.Fatal("unknown host with failOpen=false should pass for non-pinned hosts")
	}
}

func TestSPNPBroadCoveragePublicSuffix(t *testing.T) {
	rules := []SPNPHostRule{{
		Host: "com", IncludeSub: true,
		Pins: []SPNPPin{{"sha256", spnpValidPin}, {"sha256", spnpValidPin2}}}}
	r := SPNPValidateRules(rules, 1_000_000)
	if !r.HasReason(SPNPReasonHostCoverageBroad) {
		t.Fatalf("want broad coverage: %v", r.Findings)
	}
}

func TestSPNPPinSetExpired(t *testing.T) {
	rules := []SPNPHostRule{{
		Host: "a.example", NotAfter: 1000,
		Pins: []SPNPPin{{"sha256", spnpValidPin}, {"sha256", spnpValidPin2}}}}
	r := SPNPValidateRules(rules, 2000)
	if !r.HasReason(SPNPReasonPinSetExpired) {
		t.Fatalf("want expired pin set: %v", r.Findings)
	}
}

func TestSPNPPinSetNotYetValid(t *testing.T) {
	rules := []SPNPHostRule{{
		Host: "a.example", NotBefore: 5000,
		Pins: []SPNPPin{{"sha256", spnpValidPin}, {"sha256", spnpValidPin2}}}}
	r := SPNPValidateRules(rules, 2000)
	if !r.HasReason(SPNPReasonPinSetNotYetValid) {
		t.Fatalf("want not yet valid: %v", r.Findings)
	}
}
