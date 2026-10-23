package main

import "testing"

func TestVRValidRange(t *testing.T) {
	if safe, _ := VRAuditConstraint(">=1.20.0 <1.21.0"); !safe {
		t.Fatal("normal bounded range should pass")
	}
}

func TestVRInvertedRange(t *testing.T) {
	_, fs := VRAuditConstraint(">=1.21.0 <1.20.0")
	if !VRHasReason(fs, VRReasonRangeInverted) {
		t.Fatalf("lower above upper must flag: %v", fs)
	}
}

func TestVREmpty(t *testing.T) {
	_, fs := VRAuditConstraint("   ")
	if !VRHasReason(fs, VRReasonEmptyConstraint) {
		t.Fatalf("empty constraint must flag: %v", fs)
	}
}

func TestVRBadOperator(t *testing.T) {
	_, fs := VRAuditConstraint(">><1.0.0")
	if !VRHasReason(fs, VRReasonBadOperator) {
		t.Fatalf("malformed operator token must flag: %v", fs)
	}
}

func TestVRBadOperand(t *testing.T) {
	_, fs := VRAuditConstraint(">=1.abc")
	if !VRHasReason(fs, VRReasonBadOperator) {
		t.Fatalf("non-semver operand must flag: %v", fs)
	}
}

func TestVRLeadingZeroOperand(t *testing.T) {
	_, fs := VRAuditConstraint(">=01.2.0")
	if !VRHasReason(fs, VRReasonBadOperator) {
		t.Fatalf("leading-zero version must be rejected: %v", fs)
	}
}

func TestVRWildcardLegal(t *testing.T) {
	for _, e := range []string{">=1.20.x", "*", "1.x", "1.20.*"} {
		if safe, _ := VRAuditConstraint(e); !safe {
			t.Fatalf("legal wildcard constraint %q should pass", e)
		}
	}
}

func TestVRWildcardIllegal(t *testing.T) {
	_, fs := VRAuditConstraint(">=1.2x.0")
	if !VRHasReason(fs, VRReasonWildcardPosition) {
		t.Fatalf("mid-component wildcard must flag: %v", fs)
	}
}

func TestVRCaretTildeTreatedAsLower(t *testing.T) {
	// ^1.4.0 下界 1.4.0，配合 <2.0.0 不颠倒
	if safe, _ := VRAuditConstraint("^1.4.0 <2.0.0"); !safe {
		t.Fatal("caret lower bound below upper should pass")
	}
}
