package main

import "testing"

func jegHas(fs []JEGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestJEGCleanMod(t *testing.T) {
	pol := DefaultJEGPolicy()
	entries := []JEGEntry{
		{Name: "fabric.mod.json"},
		{Name: "com/example/Mod.class"},
		{Name: "assets/m/icon.png"},
	}
	safe, fs := JEGAudit(entries, pol)
	// 普通模组无 SPI/签名/可执行，应安全
	if !safe {
		t.Fatalf("clean mod should pass, got %v", fs)
	}
}

func TestJEGSlip(t *testing.T) {
	pol := DefaultJEGPolicy()
	entries := []JEGEntry{{Name: "../../../AppData/x.class"}}
	_, fs := JEGAudit(entries, pol)
	if !jegHas(fs, JEGReasonSlipPath) {
		t.Fatalf("want slip, got %v", fs)
	}
}

func TestJEGAbsolute(t *testing.T) {
	pol := DefaultJEGPolicy()
	entries := []JEGEntry{{Name: "/etc/passwd"}}
	_, fs := JEGAudit(entries, pol)
	if !jegHas(fs, JEGReasonAbsoluteEntry) {
		t.Fatalf("want absolute, got %v", fs)
	}
}

func TestJEGDuplicate(t *testing.T) {
	pol := DefaultJEGPolicy()
	entries := []JEGEntry{
		{Name: "com/x/A.class"},
		{Name: "com/x/A.class"},
	}
	_, fs := JEGAudit(entries, pol)
	if !jegHas(fs, JEGReasonDuplicateEntry) {
		t.Fatalf("want duplicate, got %v", fs)
	}
}

func TestJEGCaseCollision(t *testing.T) {
	pol := DefaultJEGPolicy()
	entries := []JEGEntry{
		{Name: "com/x/Foo.class"},
		{Name: "com/x/foo.class"},
	}
	_, fs := JEGAudit(entries, pol)
	if !jegHas(fs, JEGReasonCaseCollision) {
		t.Fatalf("want case collision, got %v", fs)
	}
}

func TestJEGSignature(t *testing.T) {
	pol := DefaultJEGPolicy()
	entries := []JEGEntry{{Name: "META-INF/MANIFEST.MF"}, {Name: "META-INF/CERT.RSA"}}
	_, fs := JEGAudit(entries, pol)
	if !jegHas(fs, JEGReasonSignatureArtifact) {
		t.Fatalf("want signature artifact, got %v", fs)
	}
}

func TestJEGServiceInject(t *testing.T) {
	pol := DefaultJEGPolicy()
	entries := []JEGEntry{{Name: "META-INF/services/com.example.SPI"}}
	_, fs := JEGAudit(entries, pol)
	if !jegHas(fs, JEGReasonServiceInject) {
		t.Fatalf("want service inject, got %v", fs)
	}
}

func TestJEGBootPackage(t *testing.T) {
	pol := DefaultJEGPolicy()
	entries := []JEGEntry{{Name: "java/lang/Runtime.class"}}
	_, fs := JEGAudit(entries, pol)
	if !jegHas(fs, JEGReasonBootClassPath) {
		t.Fatalf("want boot package, got %v", fs)
	}
}

func TestJEGExecutable(t *testing.T) {
	pol := DefaultJEGPolicy()
	entries := []JEGEntry{{Name: "native/evil.dll"}}
	_, fs := JEGAudit(entries, pol)
	if !jegHas(fs, JEGReasonExecutableMember) {
		t.Fatalf("want executable, got %v", fs)
	}
}

func TestJEGMultiRelease(t *testing.T) {
	pol := DefaultJEGPolicy()
	entries := []JEGEntry{{Name: "META-INF/versions/11/com/x/A.class"}}
	_, fs := JEGAudit(entries, pol)
	if !jegHas(fs, JEGReasonMultiRelease) {
		t.Fatalf("want multi-release, got %v", fs)
	}
}

func TestJEGMultiReleaseAllowed(t *testing.T) {
	pol := DefaultJEGPolicy()
	pol.AllowMultiRelease = true
	entries := []JEGEntry{{Name: "META-INF/versions/11/com/x/A.class"}}
	safe, fs := JEGAudit(entries, pol)
	if !safe {
		t.Fatalf("multi-release allowed should pass, got %v", fs)
	}
}
