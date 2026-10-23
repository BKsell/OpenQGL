package main

import "testing"

func prxHas(fs []PRXFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPRXGoodHTTPSProxy(t *testing.T) {
	safe, _ := PRXValidateConfig(PRXView{ProxyURL: "https://proxy.corp.test:8443"})
	if !safe {
		t.Fatal("https proxy without creds should pass")
	}
}

func TestPRXCredentials(t *testing.T) {
	_, fs := PRXValidateConfig(PRXView{ProxyURL: "http://user:pw@proxy.test:8080", HasCredentials: true})
	if !prxHas(fs, PRXReasonCredentialsInURL) {
		t.Fatalf("want creds in url, got %v", fs)
	}
}

func TestPRXCleartextWithCreds(t *testing.T) {
	_, fs := PRXValidateConfig(PRXView{ProxyURL: "http://user:pw@proxy.test:8080"})
	if !prxHas(fs, PRXReasonPlainHTTPProxy) {
		t.Fatalf("want cleartext creds, got %v", fs)
	}
}

func TestPRXBadScheme(t *testing.T) {
	_, fs := PRXValidateConfig(PRXView{ProxyURL: "ftp://proxy.test"})
	if !prxHas(fs, PRXReasonNonHTTPScheme) {
		t.Fatalf("want bad scheme, got %v", fs)
	}
}

func TestPRXPACCleartext(t *testing.T) {
	_, fs := PRXValidateConfig(PRXView{ProxyURL: "https://proxy.test", PACURL: "http://pac.test/wpad.pac"})
	if !prxHas(fs, PRXReasonPacOverCleartext) {
		t.Fatalf("want pac cleartext, got %v", fs)
	}
}

func TestPRXNoProxyStar(t *testing.T) {
	_, fs := PRXValidateConfig(PRXView{ProxyURL: "https://proxy.test", NoProxyRules: []string{"*"}})
	if !prxHas(fs, PRXReasonNoProxyTooBroad) {
		t.Fatalf("want broad noproxy, got %v", fs)
	}
}

func TestPRXNoProxyDotCom(t *testing.T) {
	_, fs := PRXValidateConfig(PRXView{ProxyURL: "https://proxy.test", NoProxyRules: []string{".com"}})
	if !prxHas(fs, PRXReasonNoProxyTooBroad) {
		t.Fatalf("want .com broad, got %v", fs)
	}
}

func TestPRXLoopbackBypassed(t *testing.T) {
	safe, _ := PRXValidateRouting(PRXTarget{Host: "127.0.0.1", IsLoopback: true},
		[]string{"127.0.0.1", "localhost"})
	if !safe {
		t.Fatal("loopback bypassed should pass")
	}
}

func TestPRXLoopbackNotBypassed(t *testing.T) {
	_, fs := PRXValidateRouting(PRXTarget{Host: "127.0.0.1", IsLoopback: true}, nil)
	if !prxHas(fs, PRXReasonInternalViaProxy) {
		t.Fatalf("want loopback upstream, got %v", fs)
	}
}

func TestPRXMetadataNotBypassed(t *testing.T) {
	_, fs := PRXValidateRouting(PRXTarget{Host: "169.254.169.254", IsMetadata: true}, nil)
	if !prxHas(fs, PRXReasonMetadataViaProxy) {
		t.Fatalf("want metadata upstream, got %v", fs)
	}
}

func TestPRXMetadataBypassed(t *testing.T) {
	safe, _ := PRXValidateRouting(PRXTarget{Host: "169.254.169.254", IsMetadata: true},
		[]string{"169.254.169.254"})
	if !safe {
		t.Fatal("metadata bypassed should pass")
	}
}

func TestPRXPrivateSuffixRule(t *testing.T) {
	// 后缀规则 .internal 命中 host
	if !prxRuleMatches(".internal", "auth.svc.internal") {
		t.Fatal("dot suffix rule should match subdomain")
	}
	if prxRuleMatches(".internal", "evilinternal") {
		t.Fatal("dot suffix must not match bare concatenation")
	}
}
