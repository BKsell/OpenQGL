package main

import "testing"

func idnHasReason(fs []IDNFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestIDNPureLatinSafe(t *testing.T) {
	if f := IDNScanHost("launcher.example.com", DefaultIDNPolicy()); len(f) != 0 {
		t.Fatalf("pure ascii host must pass: %v", f)
	}
}

func TestIDNMixedCyrillic(t *testing.T) {
	pol := DefaultIDNPolicy()
	// 西里尔 а + 拉丁 pple，同形字冒充 apple。
	host := "\u0430pple.example.com"
	f := IDNScanHost(host, pol)
	if !idnHasReason(f, IDNReasonCyrillicLookalike) && !idnHasReason(f, IDNReasonMixedScripts) {
		t.Fatalf("mixed cyrillic/latin must be flagged: %v", f)
	}
}

func TestIDNMixedGreek(t *testing.T) {
	pol := DefaultIDNPolicy()
	// 希腊 ο U+03BF + 拉丁。
	host := "g\u03BFogle.example.com"
	f := IDNScanHost(host, pol)
	if !idnHasReason(f, IDNReasonGreekLookalike) && !idnHasReason(f, IDNReasonMixedScripts) {
		t.Fatalf("mixed greek/latin must be flagged: %v", f)
	}
}

func TestIDNPunycode(t *testing.T) {
	pol := DefaultIDNPolicy()
	if f := IDNScanHost("xn--80ak6aa92e.com", pol); !idnHasReason(f, IDNReasonPunycodeLabel) {
		t.Fatal("punycode label must be flagged")
	}
}

func TestIDNInvisible(t *testing.T) {
	pol := DefaultIDNPolicy()
	host := "pay\u200bpal.example.com"
	if f := IDNScanHost(host, pol); !idnHasReason(f, IDNReasonInvisibleChar) {
		t.Fatal("zero-width space must be flagged")
	}
}

func TestIDNConfusableAgainstKnown(t *testing.T) {
	pol := DefaultIDNPolicy()
	pol.CheckConfusableAgainst = []string{"apple"}
	// 首字符西里尔 а，骨架折叠后等于 apple。
	f := IDNScanHost("\u0430pple.com", pol)
	if !idnHasReason(f, IDNReasonConfusablePair) {
		t.Fatalf("skeleton colliding with known brand must be flagged: %v", f)
	}
}

func TestIDNEmptyAndDot(t *testing.T) {
	pol := DefaultIDNPolicy()
	if f := IDNScanHost("a..com", pol); !idnHasReason(f, IDNReasonEmptyLabel) {
		t.Fatal("empty label must be flagged")
	}
	if f := IDNScanHost(".example.com", pol); !idnHasReason(f, IDNReasonLeadingDot) {
		t.Fatal("leading dot must be flagged")
	}
}

func TestIDNPureCyrillicSingleScript(t *testing.T) {
	// 纯单一西里尔文字体系站点，默认策略允许（不算混写），但可能给 punycode 之外的信号。
	pol := DefaultIDNPolicy()
	f := IDNScanHost("\u0440\u0444.\u0440\u0444", pol)
	if idnHasReason(f, IDNReasonMixedScripts) || idnHasReason(f, IDNReasonCyrillicLookalike) {
		t.Fatalf("pure single-script cyrillic must not be treated as mixed: %v", f)
	}
}

func TestIDNIsSafe(t *testing.T) {
	if !IDNIsSafe("github.com") {
		t.Fatal("github.com must be safe")
	}
	if IDNIsSafe("\u0430pple.com") {
		t.Fatal("homograph apple must not be safe")
	}
}
