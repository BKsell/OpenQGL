package main

import (
	"testing"
)

func TestClassifyResPack_Allowed(t *testing.T) {
	d := classifyResPackURL("https://packs.example.com/rp.zip")
	if !d.Allow {
		t.Fatalf("should allow https host: %+v", d)
	}
}

func TestClassifyResPack_HttpRejected(t *testing.T) {
	d := classifyResPackURL("http://packs.example.com/rp.zip")
	if d.Allow {
		t.Fatal("http must be rejected")
	}
}

func TestClassifyResPack_UserInfoRejected(t *testing.T) {
	d := classifyResPackURL("https://user:pass@packs.example.com/rp.zip")
	if d.Allow {
		t.Fatal("userinfo must be rejected")
	}
}

func TestClassifyResPack_IPLiteralRejected(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "169.254.169.254"} {
		d := classifyResPackURL("https://" + h + "/rp.zip")
		if d.Allow {
			t.Fatalf("ip %s must be rejected: %+v", h, d)
		}
	}
}

func TestClassifyResPack_Garbage(t *testing.T) {
	if d := classifyResPackURL(""); d.Allow {
		t.Fatal("empty rejected")
	}
	if d := classifyResPackURL("ftp://x/y"); d.Allow {
		t.Fatal("ftp rejected")
	}
	if d := classifyResPackURL("://bad"); d.Allow {
		t.Fatal("parse error rejected")
	}
}

func TestAllowResPackBool(t *testing.T) {
	if !allowResPackDownload("https://a.com/r.zip") {
		t.Fatal("bool entry should allow clean https")
	}
	if allowResPackDownload("http://a.com/r.zip") {
		t.Fatal("bool entry must reject http")
	}
}
