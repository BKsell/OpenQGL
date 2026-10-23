package main

import "testing"

func wsTestPolicy() WSPolicy {
	p := DefaultWSPolicy()
	p.SecureContext = true
	p.AllowedOrigins["https://app.local"] = true
	p.AllowedHosts["ws.example.com"] = true
	return p
}

func TestWSHealthyWSS(t *testing.T) {
	p := wsTestPolicy()
	ok, fs := WSAuditUpgrade(p, "wss", "ws.example.com", "52.1.2.3",
		"https://app.local", "chat")
	if !ok {
		t.Fatalf("valid wss upgrade should pass: %v", fs)
	}
}

func TestWSOriginNotAllowed(t *testing.T) {
	p := wsTestPolicy()
	_, fs := WSAuditUpgrade(p, "wss", "ws.example.com", "52.1.2.3",
		"https://evil.example", "")
	if !WSHasReason(fs, WSReasonOriginNotAllowed) {
		t.Fatalf("want cross-site ws hijack blocked: %v", fs)
	}
}

func TestWSMixedContent(t *testing.T) {
	p := wsTestPolicy()
	_, fs := WSAuditUpgrade(p, "ws", "ws.example.com", "52.1.2.3",
		"https://app.local", "")
	if !WSHasReason(fs, WSReasonMixedContent) {
		t.Fatalf("want plaintext ws from secure context: %v", fs)
	}
}

func TestWSTargetLocalhost(t *testing.T) {
	p := wsTestPolicy()
	_, fs := WSAuditUpgrade(p, "ws", "ws.example.com", "127.0.0.1",
		"https://app.local", "")
	if !WSHasReason(fs, WSReasonTargetLocal) {
		t.Fatalf("want localhost pivot blocked: %v", fs)
	}
}

func TestWSHostNotAllowed(t *testing.T) {
	p := wsTestPolicy()
	_, fs := WSAuditUpgrade(p, "wss", "other.example.net", "52.1.2.3",
		"https://app.local", "")
	if !WSHasReason(fs, WSReasonHostNotAllowed) {
		t.Fatalf("want host not in allowlist: %v", fs)
	}
}

func TestWSSubprotocolCRLF(t *testing.T) {
	p := wsTestPolicy()
	_, fs := WSAuditUpgrade(p, "wss", "ws.example.com", "52.1.2.3",
		"https://app.local", "a\r\nX-Evil: 1")
	if !WSHasReason(fs, WSReasonSubprotocolCRLF) {
		t.Fatalf("want subprotocol CRLF injection: %v", fs)
	}
}

func TestWSSubprotocolTooLong(t *testing.T) {
	p := wsTestPolicy()
	long := ""
	for i := 0; i < p.MaxSubprotoLen+1; i++ {
		long += "a"
	}
	_, fs := WSAuditUpgrade(p, "wss", "ws.example.com", "52.1.2.3",
		"https://app.local", long)
	if !WSHasReason(fs, WSReasonSubprotocolTooLong) {
		t.Fatalf("want overlong subprotocol: %v", fs)
	}
}

func TestWSBadScheme(t *testing.T) {
	p := wsTestPolicy()
	_, fs := WSAuditUpgrade(p, "http", "ws.example.com", "52.1.2.3",
		"https://app.local", "")
	if !WSHasReason(fs, WSReasonBadScheme) {
		t.Fatalf("want bad scheme: %v", fs)
	}
}

func TestWSPrivateAllowedExplicitly(t *testing.T) {
	p := wsTestPolicy()
	p.AllowPrivate = true
	_, fs := WSAuditUpgrade(p, "wss", "ws.example.com", "192.168.1.8",
		"https://app.local", "")
	if WSHasReason(fs, WSReasonTargetLocal) {
		t.Fatalf("private should be allowed when configured: %v", fs)
	}
}
