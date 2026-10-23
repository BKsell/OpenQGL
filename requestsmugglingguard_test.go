package main

import "testing"

func TestRSNormalRequest(t *testing.T) {
	hs := []RSHeader{
		{Name: "Host", Value: "api.example.com"},
		{Name: "Content-Length", Value: "42"},
		{Name: "Authorization", Value: "Bearer xyz"},
	}
	if safe, _ := RSAuditRequestHeaders(hs); !safe {
		t.Fatal("normal request headers should be safe")
	}
}

func TestRSChunkedOnly(t *testing.T) {
	hs := []RSHeader{{Name: "Transfer-Encoding", Value: "chunked"}}
	if safe, _ := RSAuditRequestHeaders(hs); !safe {
		t.Fatal("single chunked TE should be safe")
	}
}

func TestRSCLandTE(t *testing.T) {
	hs := []RSHeader{
		{Name: "Content-Length", Value: "10"},
		{Name: "Transfer-Encoding", Value: "chunked"},
	}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonCLandTE) {
		t.Fatalf("want CL+TE smuggling: %v", fs)
	}
}

func TestRSDuplicateCLSameValue(t *testing.T) {
	hs := []RSHeader{
		{Name: "Content-Length", Value: "10"},
		{Name: "Content-Length", Value: "10"},
	}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonDuplicateCL) {
		t.Fatalf("want duplicate CL: %v", fs)
	}
	if RSHasReason(fs, RSReasonConflictingCL) {
		t.Fatalf("same value should not conflict: %v", fs)
	}
}

func TestRSConflictingCL(t *testing.T) {
	hs := []RSHeader{
		{Name: "Content-Length", Value: "10"},
		{Name: "Content-Length", Value: "20"},
	}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonConflictingCL) {
		t.Fatalf("want conflicting CL: %v", fs)
	}
}

func TestRSInvalidCLNegative(t *testing.T) {
	hs := []RSHeader{{Name: "Content-Length", Value: "-1"}}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonInvalidCL) {
		t.Fatalf("want invalid CL negative: %v", fs)
	}
}

func TestRSInvalidCLHex(t *testing.T) {
	hs := []RSHeader{{Name: "Content-Length", Value: "0x10"}}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonInvalidCL) {
		t.Fatalf("want invalid CL hex: %v", fs)
	}
}

func TestRSCLLeadingZero(t *testing.T) {
	hs := []RSHeader{{Name: "Content-Length", Value: "012"}}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonInvalidCL) {
		t.Fatalf("want leading-zero CL rejected: %v", fs)
	}
}

func TestRSMalformedTE(t *testing.T) {
	hs := []RSHeader{{Name: "Transfer-Encoding", Value: "chunked, identity"}}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonMalformedTE) {
		t.Fatalf("want malformed TE: %v", fs)
	}
	if !RSHasReason(fs, RSReasonTEWithIdentity) {
		t.Fatalf("want identity mixed in: %v", fs)
	}
}

func TestRSMultipleTE(t *testing.T) {
	hs := []RSHeader{
		{Name: "Transfer-Encoding", Value: "chunked"},
		{Name: "Transfer-Encoding", Value: "chunked"},
	}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonMultipleTE) {
		t.Fatalf("want multiple TE: %v", fs)
	}
}

func TestRSHeaderCRLFInjection(t *testing.T) {
	hs := []RSHeader{{Name: "X-Bad", Value: "a\r\nContent-Length: 0"}}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonHeaderCRLF) {
		t.Fatalf("want CRLF injection: %v", fs)
	}
}

func TestRSObsoleteFold(t *testing.T) {
	hs := []RSHeader{{Name: "X-Fold", Value: "a\r\n  continued"}}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonObsoleteLineFolding) {
		t.Fatalf("want obsolete line folding: %v", fs)
	}
}

func TestRSCaseInsensitiveName(t *testing.T) {
	hs := []RSHeader{
		{Name: "content-length", Value: "5"},
		{Name: "TRANSFER-ENCODING", Value: "chunked"},
	}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonCLandTE) {
		t.Fatalf("case-insensitive header names must still detect: %v", fs)
	}
}

func TestRSZeroCLValid(t *testing.T) {
	hs := []RSHeader{{Name: "Content-Length", Value: "0"}}
	if safe, _ := RSAuditRequestHeaders(hs); !safe {
		t.Fatal("content-length 0 is valid")
	}
}

func TestRSEmptyCLInvalid(t *testing.T) {
	hs := []RSHeader{{Name: "Content-Length", Value: "   "}}
	_, fs := RSAuditRequestHeaders(hs)
	if !RSHasReason(fs, RSReasonInvalidCL) {
		t.Fatalf("empty CL must be invalid: %v", fs)
	}
}
