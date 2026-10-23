package main

import "testing"

func TestU7CleanASCII(t *testing.T) {
	if safe, _ := U7Audit("hello <b>world</b>"); !safe {
		t.Fatal("literal ASCII angle brackets are not utf-7 and should pass this guard")
	}
}

func TestU7EscapedPlus(t *testing.T) {
	if safe, _ := U7Audit("a+-b"); !safe {
		t.Fatal("literal +- escape should be ignored")
	}
}

func TestU7EncodesLessThan(t *testing.T) {
	// +ADw- 在 UTF-7 下还原为 '<'
	_, fs := U7Audit("+ADw-script+AD4-")
	if !U7HasReason(fs, U7ReasonShiftSequence) {
		t.Fatalf("utf-7 shift sequence must flag: %v", fs)
	}
	if !U7HasReason(fs, U7ReasonEncodesAngle) {
		t.Fatalf("+ADw- decodes to '<' and must flag: %v", fs)
	}
}

func TestU7BenignBase64Word(t *testing.T) {
	// + 后即便有 base64 字符，但解码不出危险码元，不应判 angle；
	// 是否报 shift 取决于实现（带 - 终止会报 shift）。这里只确保不误报 angle。
	_, fs := U7Audit("price+bonus- here")
	if U7HasReason(fs, U7ReasonEncodesAngle) {
		t.Fatalf("ordinary word must not decode to angle: %v", fs)
	}
}

func TestU7EncodeControl(t *testing.T) {
	// +AAA- 还原为 U+0000 (NUL)
	_, fs := U7Audit("x+AAA-y")
	if !U7HasReason(fs, U7ReasonEncodesAngle) {
		t.Fatalf("utf-7 NUL encoding must flag as dangerous: %v", fs)
	}
}

func TestU7PlainPlus(t *testing.T) {
	if safe, _ := U7Audit("2+2=4"); !safe {
		t.Fatal("plain arithmetic plus should pass")
	}
}
