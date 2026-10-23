package main

import "testing"

func TestJHHealthyObject(t *testing.T) {
	r := JHResponse{ContentType: "application/json", HasNosniffHeader: true,
		BodyPrefix: `  {"a":1}`}
	if safe, _ := JHAuditResponse(r, false); !safe {
		t.Fatal("well-typed nosniff object should pass")
	}
}

func TestJHTopLevelArray(t *testing.T) {
	r := JHResponse{ContentType: "application/json", HasNosniffHeader: true,
		BodyPrefix: `[1,2,3]`}
	_, fs := JHAuditResponse(r, false)
	if !JHHasReason(fs, JHReasonTopLevelArray) {
		t.Fatalf("top-level array must flag by default: %v", fs)
	}
}

func TestJHArrayAllowedSameOrigin(t *testing.T) {
	r := JHResponse{ContentType: "application/json", HasNosniffHeader: true,
		BodyPrefix: `[1]`}
	if safe, _ := JHAuditResponse(r, true); !safe {
		t.Fatal("array allowed when explicitly same-origin hardened")
	}
}

func TestJHHtmlContentType(t *testing.T) {
	r := JHResponse{ContentType: "text/html", HasNosniffHeader: true,
		BodyPrefix: `{}`}
	_, fs := JHAuditResponse(r, false)
	if !JHHasReason(fs, JHReasonContentTypeSniffable) {
		t.Fatalf("html content-type for json must flag: %v", fs)
	}
}

func TestJHMissingNosniff(t *testing.T) {
	r := JHResponse{ContentType: "application/json", BodyPrefix: `{}`}
	_, fs := JHAuditResponse(r, false)
	if !JHHasReason(fs, JHReasonMissingNosniff) {
		t.Fatalf("missing nosniff must flag: %v", fs)
	}
}

func TestJHJSONP(t *testing.T) {
	r := JHResponse{ContentType: "application/json", HasNosniffHeader: true,
		BodyPrefix: `callback({"secret":1})`}
	_, fs := JHAuditResponse(r, false)
	if !JHHasReason(fs, JHReasonJSONPWrapper) {
		t.Fatalf("JSONP wrapper must flag: %v", fs)
	}
}

func TestJHJSONPDotted(t *testing.T) {
	r := JHResponse{ContentType: "application/json", HasNosniffHeader: true,
		BodyPrefix: `angular.callbacks._0([1])`}
	_, fs := JHAuditResponse(r, false)
	if !JHHasReason(fs, JHReasonJSONPWrapper) {
		t.Fatalf("dotted JSONP callback must flag: %v", fs)
	}
}

func TestJHExecutablePrefix(t *testing.T) {
	r := JHResponse{ContentType: "application/json", HasNosniffHeader: true,
		BodyPrefix: `var x=[1]`}
	_, fs := JHAuditResponse(r, false)
	if !JHHasReason(fs, JHReasonExecutablePrefix) {
		t.Fatalf("executable prefix must flag: %v", fs)
	}
}

func TestJHBOMStripped(t *testing.T) {
	r := JHResponse{ContentType: "application/json", HasNosniffHeader: true,
		BodyPrefix: "\xef\xbb\xbf{}"}
	if safe, _ := JHAuditResponse(r, false); !safe {
		t.Fatal("BOM-prefixed object should still parse as object")
	}
}
