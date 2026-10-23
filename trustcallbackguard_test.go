package main

import (
	"errors"
	"testing"
)

func tcbHas(fs []TCBFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

// tcbGood 描述一个完整覆盖链/时间/主机名的回调。
func tcbGood() TCBView {
	return TCBView{
		Host:                   "api.test",
		VerifiesChainSignature: true, ChecksNotBeforeAfter: true, ChecksHostnameSAN: true,
	}
}

func TestTCBGood(t *testing.T) {
	safe, _ := TCBEvaluate(tcbGood())
	if !safe {
		t.Fatal("full verification callback should pass")
	}
}

func TestTCBGoodPinNoHostname(t *testing.T) {
	v := tcbGood()
	v.ChecksHostnameSAN = false
	v.PinSetEmpty = false
	v.PinPrefixOnly = false
	safe, _ := TCBEvaluate(v)
	if !safe {
		t.Fatal("strong pin without hostname check should pass")
	}
}

func TestTCBAlwaysNil(t *testing.T) {
	v := tcbGood()
	v.AlwaysReturnsNil = true
	_, fs := TCBEvaluate(v)
	if !tcbHas(fs, TCBReasonCallbackAlwaysNil) {
		t.Fatalf("want always nil, got %v", fs)
	}
}

func TestTCBSwallowsErr(t *testing.T) {
	v := tcbGood()
	v.IgnoresIncomingErr = true
	_, fs := TCBEvaluate(v)
	if !tcbHas(fs, TCBReasonErrorSwallowed) {
		t.Fatalf("want error swallowed, got %v", fs)
	}
}

func TestTCBPresenceOnly(t *testing.T) {
	v := tcbGood()
	v.VerifiesChainSignature = false
	v.ChecksNotBeforeAfter = false
	v.ChecksHostnameSAN = false
	v.OnlyChecksPresence = true
	_, fs := TCBEvaluate(v)
	if !tcbHas(fs, TCBReasonOnlyChecksPresence) {
		t.Fatalf("want presence only, got %v", fs)
	}
}

func TestTCBEmptyPin(t *testing.T) {
	v := tcbGood()
	v.ChecksHostnameSAN = false
	v.PinSetEmpty = true
	_, fs := TCBEvaluate(v)
	if !tcbHas(fs, TCBReasonEmptyPinSet) {
		t.Fatalf("want empty pin, got %v", fs)
	}
}

func TestTCBPrefixPin(t *testing.T) {
	v := tcbGood()
	v.ChecksHostnameSAN = false
	v.PinSetEmpty = false
	v.PinPrefixOnly = true
	_, fs := TCBEvaluate(v)
	if !tcbHas(fs, TCBReasonPinPrefixOnly) {
		t.Fatalf("want prefix pin, got %v", fs)
	}
}

func TestTCBNoExpiry(t *testing.T) {
	v := tcbGood()
	v.ChecksNotBeforeAfter = false
	_, fs := TCBEvaluate(v)
	if !tcbHas(fs, TCBReasonNoExpiryCheck) {
		t.Fatalf("want no expiry, got %v", fs)
	}
}

func TestTCBNoChain(t *testing.T) {
	v := tcbGood()
	v.VerifiesChainSignature = false
	_, fs := TCBEvaluate(v)
	if !tcbHas(fs, TCBReasonNoChainVerification) {
		t.Fatalf("want no chain, got %v", fs)
	}
}

func TestTCBInsecureIncomplete(t *testing.T) {
	v := tcbGood()
	v.VerifiesChainSignature = false
	v.InsecureSkipVerifySet = true
	_, fs := TCBEvaluate(v)
	if !tcbHas(fs, TCBReasonInsecureAndWeakCB) {
		t.Fatalf("want insecure weak callback, got %v", fs)
	}
}

func TestTCBInsecureComplete(t *testing.T) {
	v := tcbGood()
	v.InsecureSkipVerifySet = true
	safe, _ := TCBEvaluate(v)
	if !safe {
		t.Fatal("insecure skip with complete callback should pass")
	}
}

func TestTCBExpectError(t *testing.T) {
	if reject, _ := TCBExpectError(errors.New("x509"), true); !reject {
		t.Fatal("non-nil verify error must reject")
	}
	if reject, _ := TCBExpectError(nil, false); !reject {
		t.Fatal("missing certs must reject")
	}
	if reject, _ := TCBExpectError(nil, true); reject {
		t.Fatal("clean verify with certs should not reject")
	}
}
