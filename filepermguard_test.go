package main

import "testing"

func fpmHas(fs []FPMFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestFPMGoodToken(t *testing.T) {
	safe, _ := FPMEvaluate(FPMView{Path: "auth.json", ModePerm: 0600,
		Sensitive: FPMKindToken, OwnerIsCurrent: true})
	if !safe {
		t.Fatal("0600 owner token should pass")
	}
}

func TestFPMWorldReadableToken(t *testing.T) {
	_, fs := FPMEvaluate(FPMView{Path: "auth.json", ModePerm: 0644,
		Sensitive: FPMKindToken, OwnerIsCurrent: true})
	if !fpmHas(fs, FPMReasonWorldReadable) {
		t.Fatalf("want world readable, got %v", fs)
	}
}

func TestFPMGroupReadableToken(t *testing.T) {
	_, fs := FPMEvaluate(FPMView{Path: "auth.json", ModePerm: 0640,
		Sensitive: FPMKindToken, OwnerIsCurrent: true})
	if !fpmHas(fs, FPMReasonGroupReadable) {
		t.Fatalf("want group readable token, got %v", fs)
	}
}

func TestFPMConfigGroupReadOK(t *testing.T) {
	// 普通 config 允许 0640
	safe, _ := FPMEvaluate(FPMView{Path: "config.json", ModePerm: 0640,
		Sensitive: FPMKindConfig, OwnerIsCurrent: true})
	if !safe {
		t.Fatal("0640 config should pass")
	}
}

func TestFPMWorldWritable(t *testing.T) {
	_, fs := FPMEvaluate(FPMView{Path: "x", ModePerm: 0666,
		Sensitive: FPMKindNormal, OwnerIsCurrent: true})
	if !fpmHas(fs, FPMReasonWorldWritable) {
		t.Fatalf("want world writable, got %v", fs)
	}
}

func TestFPMDirGroupWritable(t *testing.T) {
	_, fs := FPMEvaluate(FPMView{Path: "mods", IsDir: true, ModePerm: 0770,
		Sensitive: FPMKindNormal, OwnerIsCurrent: true})
	if !fpmHas(fs, FPMReasonDirWorldWritable) {
		t.Fatalf("want dir group writable, got %v", fs)
	}
}

func TestFPMPrivateKeyGood(t *testing.T) {
	safe, _ := FPMEvaluate(FPMView{Path: "id_ed25519", ModePerm: 0600,
		Sensitive: FPMKindPrivateKey, OwnerIsCurrent: true})
	if !safe {
		t.Fatal("0600 private key should pass")
	}
}

func TestFPMPrivateKeyGroup(t *testing.T) {
	_, fs := FPMEvaluate(FPMView{Path: "id_ed25519", ModePerm: 0640,
		Sensitive: FPMKindPrivateKey, OwnerIsCurrent: true})
	if !fpmHas(fs, FPMReasonGroupReadable) {
		t.Fatalf("want group-read private key, got %v", fs)
	}
}

func TestFPMSetuid(t *testing.T) {
	_, fs := FPMEvaluate(FPMView{Path: "data", ModePerm: 04600,
		Sensitive: FPMKindNormal, OwnerIsCurrent: true})
	if !fpmHas(fs, FPMReasonSetuidSetgid) {
		t.Fatalf("want setuid, got %v", fs)
	}
}

func TestFPMForeignOwner(t *testing.T) {
	_, fs := FPMEvaluate(FPMView{Path: "auth.json", ModePerm: 0600,
		Sensitive: FPMKindToken, OwnerIsCurrent: false})
	if !fpmHas(fs, FPMReasonForeignOwner) {
		t.Fatalf("want foreign owner, got %v", fs)
	}
}

func TestFPMWindowsWeakACL(t *testing.T) {
	_, fs := FPMEvaluate(FPMView{Path: "auth.json", ModePerm: 0600,
		Sensitive: FPMKindToken, OwnerIsCurrent: true, WindowsWeakACL: true})
	if !fpmHas(fs, FPMReasonWindowsWeakACL) {
		t.Fatalf("want weak acl, got %v", fs)
	}
}

func TestFPMRecommended(t *testing.T) {
	if FPMRecommendedPerm(FPMKindToken) != 0600 {
		t.Fatal("token should recommend 0600")
	}
	if FPMRecommendedPerm(FPMKindConfig) != 0640 {
		t.Fatal("config should recommend 0640")
	}
}
