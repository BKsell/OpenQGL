package main

import "testing"

func ungHas(r UNGResult, reason string) bool {
	return r.HasReason(reason)
}

func TestUNGPlainASCII(t *testing.T) {
	r := UNGAudit("Fabric Mods 1.20")
	if !r.Safe {
		t.Fatalf("plain ascii should be safe, got %v", r.Findings)
	}
}

func TestUNGZeroWidthSpace(t *testing.T) {
	r := UNGAudit("mod\u200bname")
	if !ungHas(r, UNGReasonZeroWidth) {
		t.Fatalf("want zero width, got %v", r.Findings)
	}
	if r.KeyStripped != "modname" {
		t.Fatalf("stripped key wrong %q", r.KeyStripped)
	}
}

func TestUNGBidiOverride(t *testing.T) {
	// RLO U+202E 可把 x.jar 显示成 rar.x
	r := UNGAudit("image\u202erar.x")
	if !ungHas(r, UNGReasonBidiControl) {
		t.Fatalf("want bidi control, got %v", r.Findings)
	}
}

func TestUNGBOM(t *testing.T) {
	r := UNGAudit("\ufeffconfig")
	if !ungHas(r, UNGReasonBOM) {
		t.Fatalf("want bom, got %v", r.Findings)
	}
}

func TestUNGSoftHyphen(t *testing.T) {
	r := UNGAudit("con\u00adfig")
	if !ungHas(r, UNGReasonSoftHyphen) {
		t.Fatalf("want soft hyphen, got %v", r.Findings)
	}
}

func TestUNGFullWidth(t *testing.T) {
	r := UNGAudit("\uff2d\uff2f\uff24\uff33")
	if !ungHas(r, UNGReasonCompatibility) {
		t.Fatalf("want fullwidth compat, got %v", r.Findings)
	}
}

func TestUNGLigature(t *testing.T) {
	r := UNGAudit("a\ufb01le")
	if !ungHas(r, UNGReasonCompatibility) {
		t.Fatalf("want ligature compat, got %v", r.Findings)
	}
}

func TestUNGNFDDecompose(t *testing.T) {
	// é = e + combining acute U+0301（NFD 形式）
	r := UNGAudit("caf\u0301")
	if !ungHas(r, UNGReasonNotNFC) {
		t.Fatalf("want nfd combining mark, got %v", r.Findings)
	}
}

func TestUNGCyrillicConfusable(t *testing.T) {
	// 西里尔小写 а U+0430 混在 ASCII 词里
	r := UNGAudit("modsаpi")
	if !ungHas(r, UNGReasonConfusableScript) {
		t.Fatalf("want mixed script confusable, got %v", r.Findings)
	}
}

func TestUNGReplacementChar(t *testing.T) {
	r := UNGAudit("mod\ufffdname")
	if !ungHas(r, UNGReasonReplacementChar) {
		t.Fatalf("want replacement char, got %v", r.Findings)
	}
}

func TestUNGOverlong(t *testing.T) {
	// 过长编码的 '/' ：0xC0 0xAF
	r := UNGAudit(string([]byte{0x6D, 0xC0, 0xAF, 0x64}))
	if !ungHas(r, UNGReasonOverlongUTF8) {
		t.Fatalf("want overlong utf8, got %v", r.Findings)
	}
}

func TestUNGStrayContinuation(t *testing.T) {
	r := UNGAudit(string([]byte{0x6D, 0x80, 0x64}))
	if !ungHas(r, UNGReasonContinuation) {
		t.Fatalf("want stray continuation, got %v", r.Findings)
	}
}

func TestUNGTruncatedSequence(t *testing.T) {
	// 三字节起始但只有一个续字节
	r := UNGAudit(string([]byte{0xE4, 0xB8, 0x6D}))
	if !ungHas(r, UNGReasonContinuation) {
		t.Fatalf("want truncated sequence, got %v", r.Findings)
	}
}

func TestUNGValidCJK(t *testing.T) {
	// 正常中文"世界"是合法 UTF-8，不应报字节级问题
	r := UNGAudit("世界")
	if ungHas(r, UNGReasonOverlongUTF8) || ungHas(r, UNGReasonContinuation) ||
		ungHas(r, UNGReasonSurrogate) {
		t.Fatalf("valid CJK wrongly flagged: %v", r.Findings)
	}
}

func TestUNGStripFormatOnly(t *testing.T) {
	got := UNGStripFormat("a\u200bb\u200dc\ufeff")
	if got != "abc" {
		t.Fatalf("strip format wrong %q", got)
	}
}

func TestUNGCircleNumber(t *testing.T) {
	r := UNGAudit("version\u2460") // ①
	if !ungHas(r, UNGReasonCompatibility) {
		t.Fatalf("want circled number compat, got %v", r.Findings)
	}
}
