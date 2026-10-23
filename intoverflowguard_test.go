package main

import "testing"

func iovHas(fs []IOVFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestIOVMulOK(t *testing.T) {
	pol := DefaultIOVPolicy()
	r, safe, _ := IOVCheckedMul(1920, 1080*4, pol)
	if !safe || r != 1920*1080*4 {
		t.Fatalf("normal mul wrong r=%d safe=%v", r, safe)
	}
}

func TestIOVMulOverflow(t *testing.T) {
	pol := DefaultIOVPolicy()
	big := int64(1 << 40)
	_, safe, fs := IOVCheckedMul(big, big, pol)
	if safe {
		t.Fatal("expected overflow to be unsafe")
	}
	if !iovHas(fs, IOVReasonMulOverflow) && !iovHas(fs, IOVReasonExceedsLimit) {
		t.Fatalf("want overflow/limit, got %v", fs)
	}
}

func TestIOVMulNegative(t *testing.T) {
	pol := DefaultIOVPolicy()
	_, _, fs := IOVCheckedMul(-1, 10, pol)
	if !iovHas(fs, IOVReasonNegativeSize) {
		t.Fatalf("want negative, got %v", fs)
	}
}

func TestIOVMulExceedsLimit(t *testing.T) {
	pol := DefaultIOVPolicy()
	pol.MaxAllocation = 1024
	_, safe, fs := IOVCheckedMul(100, 100, pol)
	if safe || !iovHas(fs, IOVReasonExceedsLimit) {
		t.Fatalf("want exceeds limit, got %v", fs)
	}
}

func TestIOVAddOK(t *testing.T) {
	pol := DefaultIOVPolicy()
	r, safe, _ := IOVCheckedAdd(1000, 234, pol)
	if !safe || r != 1234 {
		t.Fatalf("add wrong r=%d", r)
	}
}

func TestIOVAddOverflow(t *testing.T) {
	pol := DefaultIOVPolicy()
	max := int64(1<<63 - 100)
	_, safe, fs := IOVCheckedAdd(max, 10, pol)
	if safe {
		t.Fatal("expected add overflow")
	}
	if !iovHas(fs, IOVReasonAddOverflow) {
		t.Fatalf("want add overflow, got %v", fs)
	}
}

func TestIOVAlignPowerOfTwo(t *testing.T) {
	pol := DefaultIOVPolicy()
	r, safe, _ := IOVCheckedAlign(13, 8, pol)
	if !safe || r != 16 {
		t.Fatalf("align wrong r=%d", r)
	}
}

func TestIOVAlignAligned(t *testing.T) {
	pol := DefaultIOVPolicy()
	r, safe, _ := IOVCheckedAlign(16, 8, pol)
	if !safe || r != 16 {
		t.Fatalf("already aligned wrong r=%d", r)
	}
}

func TestIOVAlignNonPowerOfTwo(t *testing.T) {
	pol := DefaultIOVPolicy()
	r, safe, _ := IOVCheckedAlign(10, 3, pol)
	if !safe || r != 12 {
		t.Fatalf("non-pow2 align wrong r=%d", r)
	}
}

func TestIOVAlignOverflow(t *testing.T) {
	pol := DefaultIOVPolicy()
	pol.MaxAllocation = 1<<62 - 1
	big := int64(1<<62 - 2)
	_, safe, fs := IOVCheckedAlign(big, 4096, pol)
	if safe {
		t.Fatal("align near max should overflow/limit")
	}
	if !iovHas(fs, IOVReasonAlignOverflow) && !iovHas(fs, IOVReasonExceedsLimit) {
		t.Fatalf("want align overflow, got %v", fs)
	}
}

func TestIOVZeroReject(t *testing.T) {
	pol := DefaultIOVPolicy()
	pol.RejectZero = true
	_, _, fs := IOVCheckedMul(0, 100, pol)
	if !iovHas(fs, IOVReasonZeroSize) {
		t.Fatalf("want zero reject, got %v", fs)
	}
}

func TestIOVImagePlaneSize(t *testing.T) {
	pol := DefaultIOVPolicy()
	// 典型像素缓冲 width*height*4 不应误报
	w, h := int64(3840), int64(2160)
	r, safe, _ := IOVCheckedMul(w, h, pol)
	if !safe {
		t.Fatal("4k plane base should pass limit")
	}
	r, safe, _ = IOVCheckedMul(r, 4, pol)
	if !safe || r != 3840*2160*4 {
		t.Fatalf("4k rgba size wrong r=%d", r)
	}
}
