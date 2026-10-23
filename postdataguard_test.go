package main

import "testing"

func TestPDHealthyJSON(t *testing.T) {
	req := PDRequest{Method: "POST", ContentType: "application/json",
		BodyBytes: 20, DeclaredLen: 20, MaxBodyBytes: 1024}
	if safe, _ := PDAuditRequest(req); !safe {
		t.Fatal("normal json post should pass")
	}
}

func TestPDBodyExceedsLimit(t *testing.T) {
	req := PDRequest{Method: "POST", ContentType: "application/json",
		BodyBytes: 2000, DeclaredLen: 2000, MaxBodyBytes: 1024}
	_, fs := PDAuditRequest(req)
	if !PDHasReason(fs, PDReasonBodyExceedsLimit) {
		t.Fatalf("want oversized body: %v", fs)
	}
}

func TestPDDeclaredLengthMismatch(t *testing.T) {
	req := PDRequest{Method: "POST", ContentType: "application/json",
		BodyBytes: 20, DeclaredLen: 99, MaxBodyBytes: 1024}
	_, fs := PDAuditRequest(req)
	if !PDHasReason(fs, PDReasonDeclaredLengthMismatch) {
		t.Fatalf("want declared length mismatch: %v", fs)
	}
}

func TestPDGetWithBody(t *testing.T) {
	req := PDRequest{Method: "GET", ContentType: "application/json", BodyBytes: 5}
	_, fs := PDAuditRequest(req)
	if !PDHasReason(fs, PDReasonEmptyMethodBody) {
		t.Fatalf("GET must not carry body: %v", fs)
	}
}

func TestPDSecretInQuery(t *testing.T) {
	req := PDRequest{Method: "POST", ContentType: "application/x-www-form-urlencoded",
		BodyBytes: 10, DeclaredLen: 10, MaxBodyBytes: 1024,
		URLQuery: "user=bob&password=hunter2"}
	_, fs := PDAuditRequest(req)
	if !PDHasReason(fs, PDReasonSecretInURL) {
		t.Fatalf("password must not be in url query: %v", fs)
	}
}

func TestPDSecretEncodedKey(t *testing.T) {
	req := PDRequest{Method: "POST", BodyBytes: 1, DeclaredLen: 1,
		MaxBodyBytes: 100, URLQuery: "%61ccess_token=abc"}
	_, fs := PDAuditRequest(req)
	if !PDHasReason(fs, PDReasonSecretInURL) {
		t.Fatalf("percent-encoded access_token key must be detected: %v", fs)
	}
}

func TestPDMultipartBoundary(t *testing.T) {
	okReq := PDRequest{Method: "POST",
		ContentType: "multipart/form-data; boundary=----xyz",
		BodyBytes:   30, DeclaredLen: 30, MaxBodyBytes: 1024}
	if safe, _ := PDAuditRequest(okReq); !safe {
		t.Fatal("multipart with boundary should pass")
	}
	bad := PDRequest{Method: "POST", ContentType: "multipart/form-data;",
		BodyBytes: 30, DeclaredLen: 30, MaxBodyBytes: 1024}
	_, fs := PDAuditRequest(bad)
	if !PDHasReason(fs, PDReasonMissingBoundary) {
		t.Fatalf("multipart without boundary flagged: %v", fs)
	}
}

func TestPDMultipartBoundaryCRLF(t *testing.T) {
	req := PDRequest{Method: "POST",
		ContentType: "multipart/form-data; boundary=abc\r\ndef",
		BodyBytes:   30, DeclaredLen: 30, MaxBodyBytes: 1024}
	_, fs := PDAuditRequest(req)
	if !PDHasReason(fs, PDReasonBoundaryBad) {
		t.Fatalf("boundary with CRLF flagged: %v", fs)
	}
}

func TestPDJSONEmptyBody(t *testing.T) {
	req := PDRequest{Method: "POST", ContentType: "application/json",
		BodyBytes: 0, DeclaredLen: 0, MaxBodyBytes: 1024}
	_, fs := PDAuditRequest(req)
	if !PDHasReason(fs, PDReasonContentTypeMismatch) {
		t.Fatalf("json content-type with empty body flagged: %v", fs)
	}
}
