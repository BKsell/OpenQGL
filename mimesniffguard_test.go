package main

import "testing"

func msnHasReason(fs []MSNFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestMSNKindDetection(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want int
	}{
		{"png", []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2}, MSNKindImage},
		{"jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE0}, MSNKindImage},
		{"gif", []byte("GIF89a rest"), MSNKindImage},
		{"zip", []byte("PK\x03\x04 rest"), MSNKindArchive},
		{"gz", []byte{0x1F, 0x8B, 0x08}, MSNKindArchive},
		{"pdf", []byte("%PDF-1.7"), MSNKindPDF},
		{"elf", []byte{0x7F, 'E', 'L', 'F', 0x02}, MSNKindExecutable},
		{"pe", []byte("MZ\x90\x00 fake dos"), MSNKindExecutable},
		{"class", []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00}, MSNKindExecutable},
		{"html", []byte("<html><body>x</body>"), MSNKindHTML},
		{"svg", []byte("<?xml version=\"1.0\"?><svg></svg>"), MSNKindHTML},
	}
	for _, c := range cases {
		if got := MSNSniffKind(c.body); got != c.want {
			t.Fatalf("%s kind=%d want %d", c.name, got, c.want)
		}
	}
}

func TestMSNValidImage(t *testing.T) {
	pol := DefaultMSNPolicy()
	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00}
	if f := MSNEvaluate("image/png", png, true, pol); len(f) != 0 {
		t.Fatalf("valid declared png must pass: %v", f)
	}
}

func TestMSNImageDisguisedHTML(t *testing.T) {
	pol := DefaultMSNPolicy()
	body := []byte("<html><script>steal()</script>")
	f := MSNEvaluate("image/png", body, true, pol)
	if !msnHasReason(f, MSNReasonImageIsHTML) {
		t.Fatalf("html served as image must be flagged: %v", f)
	}
}

func TestMSNExecutableMagic(t *testing.T) {
	pol := DefaultMSNPolicy()
	if f := MSNEvaluate("application/octet-stream", []byte("MZfake"), false, pol);
		!msnHasReason(f, MSNReasonMagicExecutable) {
		t.Fatal("PE magic under octet-stream must be flagged")
	}
}

func TestMSNDeclaredExecutable(t *testing.T) {
	pol := DefaultMSNPolicy()
	if f := MSNEvaluate("application/x-msdownload", []byte("PK\x03\x04x"), false, pol);
		!msnHasReason(f, MSNReasonDeclaredExecutable) {
		t.Fatal("explicitly declared download must be flagged")
	}
}

func TestMSNMismatch(t *testing.T) {
	pol := DefaultMSNPolicy()
	// 声明 application/pdf，实际 PNG。
	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	if f := MSNEvaluate("application/pdf", png, true, pol);
		!msnHasReason(f, MSNReasonMimeTypeMismatch) {
		t.Fatal("declared pdf / magic png mismatch must be flagged")
	}
}

func TestMSNSVGCarrier(t *testing.T) {
	pol := DefaultMSNPolicy()
	svg := []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"><script>a</script></svg>")
	f := MSNEvaluate("image/svg+xml", svg, true, pol)
	if !msnHasReason(f, MSNReasonSVGScriptCarrier) {
		t.Fatalf("svg script carrier must be flagged: %v", f)
	}
}

func TestMSNEmpty(t *testing.T) {
	pol := DefaultMSNPolicy()
	if f := MSNEvaluate("image/png", nil, true, pol); !msnHasReason(f, MSNReasonEmptyBody) {
		t.Fatal("empty body must be flagged")
	}
}

func TestMSNIsSafe(t *testing.T) {
	jar := []byte("PK\x03\x04 manifest stuff")
	if !MSNIsSafe("application/java-archive", jar, false) {
		t.Fatal("jar magic + jar type should be safe")
	}
}
