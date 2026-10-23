package main

import "testing"

func TestFRMHealthyFrame(t *testing.T) {
	if safe, _ := FRMAuditFrame(100, 200, 4096); !safe {
		t.Fatal("frame within bounds should pass")
	}
}

func TestFRMTooLarge(t *testing.T) {
	_, fs := FRMAuditFrame(FRMMaxFrame+1, FRMMaxFrame+1, FRMMaxFrame)
	if !FRMHasReason(fs, FRMReasonLengthTooLarge) {
		t.Fatalf("frame above max must flag: %v", fs)
	}
}

func TestFRMExceedsAvailable(t *testing.T) {
	_, fs := FRMAuditFrame(1000, 10, 4096)
	if !FRMHasReason(fs, FRMReasonLengthExceedsData) {
		t.Fatalf("declared length beyond buffer must flag: %v", fs)
	}
}

func TestFRMNegative(t *testing.T) {
	_, fs := FRMAuditFrame(-1, 100, 4096)
	if !FRMHasReason(fs, FRMReasonNegativeLength) {
		t.Fatalf("negative length must flag: %v", fs)
	}
}

func TestFRMZeroPayload(t *testing.T) {
	_, fs := FRMAuditFrame(0, 0, 4096)
	if !FRMHasReason(fs, FRMReasonZeroPayload) {
		t.Fatalf("zero payload flagged: %v", fs)
	}
}

func TestFRMNestedOverflow(t *testing.T) {
	_, fs := FRMAuditNested(200, 10, 100)
	if !FRMHasReason(fs, FRMReasonNestedOverflow) {
		t.Fatalf("inner frame beyond parent remainder must flag: %v", fs)
	}
}

func TestFRMNestedOK(t *testing.T) {
	if safe, _ := FRMAuditNested(50, 10, 100); !safe {
		t.Fatal("inner frame within remainder should pass")
	}
}

func TestFRMVarintSingle(t *testing.T) {
	v, n, ok, minimal := FRMDecodeVarint([]byte{0x01})
	if !ok || !minimal || v != 1 || n != 1 {
		t.Fatalf("single-byte varint wrong: v=%d n=%d ok=%v min=%v", v, n, ok, minimal)
	}
}

func TestFRMVarintMulti(t *testing.T) {
	v, n, ok, minimal := FRMDecodeVarint([]byte{0xAC, 0x02})
	if !ok || !minimal || v != 300 || n != 2 {
		t.Fatalf("300 varint wrong: v=%d n=%d ok=%v min=%v", v, n, ok, minimal)
	}
}

func TestFRMVarintNonMinimalZeroTail(t *testing.T) {
	_, _, ok, minimal := FRMDecodeVarint([]byte{0x80, 0x00})
	if !ok || minimal {
		t.Fatal("0x80 0x00 must be non-minimal")
	}
}

func TestFRMVarintNonMinimalSmallValue(t *testing.T) {
	_, _, ok, minimal := FRMDecodeVarint([]byte{0x80, 0x01})
	if !ok || minimal {
		t.Fatal("0x80 0x01 must be non-minimal")
	}
}

func TestFRMVarintUnterminated(t *testing.T) {
	buf := []byte{0x80, 0x80, 0x80}
	if safe, _ := FRMAuditVarint(buf); safe {
		t.Fatal("continuation with no terminator must fail")
	}
}

func TestFRMVarintTooManyBytes(t *testing.T) {
	buf := make([]byte, 11)
	for i := range buf {
		buf[i] = 0x80
	}
	if safe, _ := FRMAuditVarint(buf); safe {
		t.Fatal("11-byte varint exceeds uint64 and must fail")
	}
}
