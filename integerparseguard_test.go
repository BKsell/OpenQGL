package main

import "testing"

func TestIPPlain(t *testing.T) {
	r := IPParseSize("1024", -1)
	if !r.OK || r.Value != 1024 {
		t.Fatalf("plain int parse wrong: %+v", r)
	}
}

func TestIPSuffix(t *testing.T) {
	cases := map[string]int64{"1K": 1024, "2M": 2 << 20, "1G": 1 << 30}
	for in, want := range cases {
		r := IPParseSize(in, -1)
		if !r.OK || r.Value != want {
			t.Fatalf("%s want %d got %+v", in, want, r)
		}
	}
}

func TestIPEmpty(t *testing.T) {
	if r := IPParseSize("", -1); r.OK || !IPHasReason(r, IPReasonEmpty) {
		t.Fatalf("empty must fail: %+v", r)
	}
	if r := IPParseSize("abc", -1); !IPHasReason(r, IPReasonEmpty) {
		t.Fatalf("non-numeric must fail: %+v", r)
	}
}

func TestIPBadSuffix(t *testing.T) {
	if r := IPParseSize("10X", -1); r.OK || !IPHasReason(r, IPReasonBadSuffix) {
		t.Fatalf("bad suffix must fail: %+v", r)
	}
}

func TestIPOverflow(t *testing.T) {
	// 9223372036854775808 = 2^63，超 int64
	r := IPParseSize("9223372036854775808", -1)
	if r.OK || !IPHasReason(r, IPReasonOverflow) {
		t.Fatalf("int64 overflow must fail: %+v", r)
	}
}

func TestIPSuffixMulOverflow(t *testing.T) {
	// 大数 * G 溢出
	r := IPParseSize("9000000000000G", -1)
	if r.OK || !IPHasReason(r, IPReasonMulOverflow) {
		t.Fatalf("suffix multiplication overflow must fail: %+v", r)
	}
}

func TestIPExceedsMax(t *testing.T) {
	r := IPParseSize("5000", 1024)
	if r.OK || !IPHasReason(r, IPReasonExceedsMax) {
		t.Fatalf("value above max must fail: %+v", r)
	}
}

func TestIPCheckedMul(t *testing.T) {
	if v, ov := IPCheckedMul(100, 200); ov || v != 20000 {
		t.Fatal("normal multiply should work")
	}
	if _, ov := IPCheckedMul(1<<62, 4); !ov {
		t.Fatal("multiply overflow must be detected")
	}
	if _, ov := IPCheckedMul(-1, 10); !ov {
		t.Fatal("negative operand must be treated as overflow for sizes")
	}
}

func TestIPNegativeSize(t *testing.T) {
	if safe, _ := IPRejectNegative(-1); safe {
		t.Fatal("negative used as size must be rejected")
	}
}

func TestIPCountMismatch(t *testing.T) {
	if safe, _ := IPCheckCount(100, 2); safe {
		t.Fatal("declared count exceeding records must fail")
	}
	if safe, _ := IPCheckCount(2, 100); !safe {
		t.Fatal("count within available should pass")
	}
}
