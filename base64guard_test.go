package main

import "testing"

func TestB6Valid(t *testing.T) {
	// "hello" 的标准 base64
	if safe, _ := B6Audit("aGVsbG8="); !safe {
		t.Fatal("valid padded base64 should pass")
	}
}

func TestB6ValidNoPad(t *testing.T) {
	// "any" -> YW55 (4 字符无填充)
	if safe, _ := B6Audit("YW55"); !safe {
		t.Fatal("valid 4-char base64 without padding should pass")
	}
}

func TestB6InvalidChar(t *testing.T) {
	_, fs := B6Audit("aGVs!G8=")
	if !B6HasReason(fs, B6ReasonInvalidAlphabet) {
		t.Fatalf("non-alphabet char must flag: %v", fs)
	}
}

func TestB6DataAfterPadding(t *testing.T) {
	_, fs := B6Audit("aGVsbG8=XY")
	if !B6HasReason(fs, B6ReasonBadPadding) {
		t.Fatalf("data after padding must flag: %v", fs)
	}
}

func TestB6TooMuchPadding(t *testing.T) {
	_, fs := B6Audit("aGVs===")
	if !B6HasReason(fs, B6ReasonBadPadding) {
		t.Fatalf("three padding chars must flag: %v", fs)
	}
}

func TestB6LengthNotMultiple(t *testing.T) {
	_, fs := B6Audit("aGVsbG")
	if !B6HasReason(fs, B6ReasonBadPadding) {
		t.Fatalf("length not multiple of 4 must flag: %v", fs)
	}
}

func TestB6ControlChar(t *testing.T) {
	_, fs := B6Audit("aGVs\x00G8=")
	if !B6HasReason(fs, B6ReasonControlCharacter) {
		t.Fatalf("control character must flag: %v", fs)
	}
}

func TestB6DecodedTooLarge(t *testing.T) {
	// 构造超长合法字母表串
	buf := make([]byte, B6MaxEncoded+8)
	for i := range buf {
		buf[i] = 'A'
	}
	_, fs := B6Audit(string(buf))
	if !B6HasReason(fs, B6ReasonLengthExceedsLimit) {
		t.Fatalf("oversized encoded input must flag: %v", fs)
	}
	if !B6HasReason(fs, B6ReasonDecodedExceedsLimit) {
		t.Fatalf("oversized decoded estimate must flag: %v", fs)
	}
}

func TestB6DataURL(t *testing.T) {
	safe, isB64, payload, _ := B6AuditDataURL("data:image/png;base64,aGVsbG8=")
	if !safe || !isB64 || payload != "aGVsbG8=" {
		t.Fatalf("valid data url should parse: safe=%v b64=%v p=%q", safe, isB64, payload)
	}
}

func TestB6DataURLCRLF(t *testing.T) {
	_, _, _, fs := B6AuditDataURL("data:text/plain;\r\nbase64,aGVsbG8=")
	if !B6HasReason(fs, B6ReasonDataHeaderCRLF) {
		t.Fatalf("CRLF in data-url media section must flag: %v", fs)
	}
}
