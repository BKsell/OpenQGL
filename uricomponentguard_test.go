package main

import "testing"

func TestUCHealthy(t *testing.T) {
	in := UCAuditInput{
		FullURL: "https://api.example.com/v1/version?os=windows",
		Scheme:  "https", Host: "api.example.com",
	}
	if safe, _ := UCAudit(in); !safe {
		t.Fatal("well-formed uri should pass")
	}
}

func TestUCPortValid(t *testing.T) {
	in := UCAuditInput{FullURL: "https://h:8443/", Host: "h", Port: "8443"}
	if safe, _ := UCAudit(in); !safe {
		t.Fatal("valid port should pass")
	}
}

func TestUCPortOutOfRange(t *testing.T) {
	for _, p := range []string{"0", "70000", "-1", "abc", "99999"} {
		in := UCAuditInput{FullURL: "https://h:" + p + "/", Host: "h", Port: p}
		_, fs := UCAudit(in)
		if !UCHasReason(fs, UCReasonPortInvalid) {
			t.Fatalf("port %q must be invalid: %v", p, fs)
		}
	}
}

func TestUCEmptyHost(t *testing.T) {
	in := UCAuditInput{FullURL: "https:///path", Host: ""}
	_, fs := UCAudit(in)
	if !UCHasReason(fs, UCReasonEmptyHost) {
		t.Fatalf("empty host must flag: %v", fs)
	}
}

func TestUCUserInfo(t *testing.T) {
	in := UCAuditInput{FullURL: "https://u:p@h/", Host: "h", HasUserInfo: true}
	_, fs := UCAudit(in)
	if !UCHasReason(fs, UCReasonUserInfo) {
		t.Fatalf("embedded credentials must flag: %v", fs)
	}
}

func TestUCBadPercent(t *testing.T) {
	in := UCAuditInput{FullURL: "https://h/a%zz", Host: "h"}
	_, fs := UCAudit(in)
	if !UCHasReason(fs, UCReasonBadPercent) {
		t.Fatalf("malformed percent encoding must flag: %v", fs)
	}
	in2 := UCAuditInput{FullURL: "https://h/a%2", Host: "h"}
	_, fs2 := UCAudit(in2)
	if !UCHasReason(fs2, UCReasonBadPercent) {
		t.Fatalf("truncated percent encoding must flag: %v", fs2)
	}
}

func TestUCGoodPercent(t *testing.T) {
	in := UCAuditInput{FullURL: "https://h/a%20b", Host: "h"}
	if safe, _ := UCAudit(in); !safe {
		t.Fatal("valid %20 should pass")
	}
}

func TestUCHostOverlong(t *testing.T) {
	longLabel := ""
	for i := 0; i < 70; i++ {
		longLabel += "a"
	}
	in := UCAuditInput{FullURL: "https://" + longLabel + ".com/", Host: longLabel + ".com"}
	_, fs := UCAudit(in)
	if !UCHasReason(fs, UCReasonHostOverlong) {
		t.Fatalf("overlong label must flag: %v", fs)
	}
}

func TestUCIPv6SkipsLabelRules(t *testing.T) {
	in := UCAuditInput{FullURL: "https://[2001:db8::1]/", Host: "2001:db8::1"}
	if safe, _ := UCAudit(in); !safe {
		t.Fatal("valid bracketed ipv6 host should pass")
	}
}

func TestUCMultipleColonV4(t *testing.T) {
	in := UCAuditInput{FullURL: "https://1.2.3.4:80:90/", Host: "1.2.3.4:80"}
	_, fs := UCAudit(in)
	if !UCHasReason(fs, UCReasonMultiplePorts) {
		t.Fatalf("multiple colons in v4 host must flag: %v", fs)
	}
}
