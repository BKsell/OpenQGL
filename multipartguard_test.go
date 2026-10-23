package main

import "testing"

func mpHasReason(fs []MPFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestMPValidImageUpload(t *testing.T) {
	pol := DefaultMPPolicy()
	parts := []MPPart{
		{Name: "avatar", Filename: "face.png", Size: 1024, DeclaredKind: MSNKindImage, MagicKind: MSNKindImage, HasMagic: true},
	}
	ct := "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
	if f := MPEvaluateRequest("----WebKitFormBoundary7MA4YWxkTrZu0gW", ct, parts, 1024, pol); len(f) != 0 {
		t.Fatalf("valid image upload must pass: %v", f)
	}
}

func TestMPBoundaryTooShort(t *testing.T) {
	pol := DefaultMPPolicy()
	if f := MPEvaluateRequest("ab", "multipart/form-data; boundary=ab", nil, 0, pol);
		!mpHasReason(f, MPReasonBoundaryTooShort) {
		t.Fatal("short boundary must be flagged")
	}
}

func TestMPBoundaryBadChar(t *testing.T) {
	pol := DefaultMPPolicy()
	if f := MPEvaluateRequest("bad boundary with space!!", "", nil, 0, pol);
		!mpHasReason(f, MPReasonBoundaryBadChars) {
		t.Fatal("boundary with whitespace must be flagged")
	}
}

func TestMPFilenameTraversal(t *testing.T) {
	pol := DefaultMPPolicy()
	parts := []MPPart{
		{Name: "f", Filename: "../../../etc/passwd", Size: 10},
	}
	if f := MPEvaluateRequest("LongEnoughBoundary12345678", "", parts, 10, pol);
		!mpHasReason(f, MPReasonFilenameTraversal) {
		t.Fatal("traversal filename must be flagged")
	}
}

func TestMPFilenameDrive(t *testing.T) {
	pol := DefaultMPPolicy()
	parts := []MPPart{{Name: "f", Filename: "C:\\Windows\\x.dll", Size: 10}}
	if f := MPEvaluateRequest("LongEnoughBoundary12345678", "", parts, 10, pol);
		!mpHasReason(f, MPReasonFilenameAbsolute) {
		t.Fatal("drive filename must be flagged")
	}
}

func TestMPFilenameControl(t *testing.T) {
	pol := DefaultMPPolicy()
	parts := []MPPart{{Name: "f", Filename: "a\x00b.png", Size: 10}}
	if f := MPEvaluateRequest("LongEnoughBoundary12345678", "", parts, 10, pol);
		!mpHasReason(f, MPReasonFilenameControl) {
		t.Fatal("NUL in filename must be flagged")
	}
}

func TestMPPartAndBodySize(t *testing.T) {
	pol := DefaultMPPolicy()
	parts := []MPPart{{Name: "big", Filename: "big.zip", Size: pol.MaxPartBytes + 1}}
	f := MPEvaluateRequest("LongEnoughBoundary12345678", "", parts, pol.MaxPartBytes+1, pol)
	if !mpHasReason(f, MPReasonPartTooLarge) || !mpHasReason(f, MPReasonBodyTooLarge) {
		t.Fatal("oversized part/body must be flagged")
	}
}

func TestMPHeaderCRLF(t *testing.T) {
	pol := DefaultMPPolicy()
	ct := "multipart/form-data; boundary=LongEnoughBoundary12345678\r\nX-Inject: 1"
	if f := MPEvaluateRequest("LongEnoughBoundary12345678", ct, nil, 0, pol);
		!mpHasReason(f, MPReasonHeaderCRLF) {
		t.Fatal("CRLF in content-type must be flagged")
	}
}

func TestMPExtensionMagicMismatch(t *testing.T) {
	pol := DefaultMPPolicy()
	parts := []MPPart{
		{Name: "a", Filename: "pic.png", Size: 8, MagicKind: MSNKindHTML, HasMagic: true},
	}
	if f := MPEvaluateRequest("LongEnoughBoundary12345678", "", parts, 8, pol);
		!mpHasReason(f, MPReasonFilenameTypeMismatch) {
		t.Fatal("png name with html magic must be flagged")
	}
}

func TestMPTooManyParts(t *testing.T) {
	pol := DefaultMPPolicy()
	parts := make([]MPPart, 0, pol.MaxParts+1)
	for i := 0; i < pol.MaxParts+1; i++ {
		parts = append(parts, MPPart{Name: "f", Size: 1})
	}
	if f := MPEvaluateRequest("LongEnoughBoundary12345678", "", parts, int64(len(parts)), pol);
		!mpHasReason(f, MPReasonTooManyParts) {
		t.Fatal("too many parts must be flagged")
	}
}
