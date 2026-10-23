package main

import "testing"

func dlfHas(fs []DLFFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestDLFClean(t *testing.T) {
	pol := DefaultDLFPolicy()
	base, safe, _ := DLFSanitize("fabric-api-0.92.jar", pol)
	if !safe || base != "fabric-api-0.92.jar" {
		t.Fatalf("clean name wrong base=%q safe=%v", base, safe)
	}
}

func TestDLFTraversal(t *testing.T) {
	pol := DefaultDLFPolicy()
	base, _, fs := DLFSanitize(`../../AppData/Roaming/mods/x.jar`, pol)
	if !dlfHas(fs, DLFReasonPathTraversal) {
		t.Fatalf("want traversal, got %v", fs)
	}
	if base != "x.jar" {
		t.Fatalf("basename not extracted: %q", base)
	}
}

func TestDLFAbsoluteUNC(t *testing.T) {
	pol := DefaultDLFPolicy()
	_, _, fs := DLFSanitize(`\\evil\share\p.jar`, pol)
	if !dlfHas(fs, DLFReasonAbsolutePath) {
		t.Fatalf("want unc, got %v", fs)
	}
}

func TestDLFDriveAbsolute(t *testing.T) {
	pol := DefaultDLFPolicy()
	base, _, fs := DLFSanitize(`C:\Windows\Temp\a.jar`, pol)
	if !dlfHas(fs, DLFReasonAbsolutePath) {
		t.Fatalf("want drive absolute, got %v", fs)
	}
	if base != "a.jar" {
		t.Fatalf("base wrong %q", base)
	}
}

func TestDLFReservedDevice(t *testing.T) {
	pol := DefaultDLFPolicy()
	base, _, fs := DLFSanitize("CON.txt", pol)
	if !dlfHas(fs, DLFReasonReservedDevice) {
		t.Fatalf("want device, got %v", fs)
	}
	if base == "CON.txt" {
		t.Fatalf("device name must be replaced, got %q", base)
	}
}

func TestDLFCom1(t *testing.T) {
	pol := DefaultDLFPolicy()
	_, _, fs := DLFSanitize("com1.jar", pol)
	if !dlfHas(fs, DLFReasonReservedDevice) {
		t.Fatalf("want com1 device, got %v", fs)
	}
}

func TestDLFTrailingDot(t *testing.T) {
	pol := DefaultDLFPolicy()
	base, _, fs := DLFSanitize("mod.jar.", pol)
	if !dlfHas(fs, DLFReasonTrailingSpaceDot) {
		t.Fatalf("want trailing dot, got %v", fs)
	}
	if base != "mod.jar" {
		t.Fatalf("trailing dot not stripped: %q", base)
	}
}

func TestDLFADS(t *testing.T) {
	pol := DefaultDLFPolicy()
	base, _, fs := DLFSanitize("mod.jar:evil", pol)
	if !dlfHas(fs, DLFReasonADS) {
		t.Fatalf("want ads, got %v", fs)
	}
	if base != "mod.jar" {
		t.Fatalf("ads not removed: %q", base)
	}
}

func TestDLFCRLF(t *testing.T) {
	pol := DefaultDLFPolicy()
	_, _, fs := DLFSanitize("a.jar\r\nB: 1", pol)
	if !dlfHas(fs, DLFReasonHeaderCRLF) {
		t.Fatalf("want crlf, got %v", fs)
	}
}

func TestDLFPercentTraversal(t *testing.T) {
	pol := DefaultDLFPolicy()
	_, _, fs := DLFSanitize("%2e%2e%2f%2e%2e%2fx.jar", pol)
	if !dlfHas(fs, DLFReasonPathTraversal) {
		t.Fatalf("want encoded traversal, got %v", fs)
	}
}

func TestDLFFilenameStar(t *testing.T) {
	pol := DefaultDLFPolicy()
	// RFC5987: filename*=UTF-8''%E4%B8%AD.jar
	base, safe, _ := DLFSanitize("UTF-8''res.jar", pol)
	if !safe || base != "res.jar" {
		t.Fatalf("filename* prefix not stripped: %q safe=%v", base, safe)
	}
}

func TestDLFBadPercent(t *testing.T) {
	pol := DefaultDLFPolicy()
	_, _, fs := DLFSanitize("a%zz.jar", pol)
	if !dlfHas(fs, DLFReasonBadPercentEncoding) {
		t.Fatalf("want bad percent, got %v", fs)
	}
}

func TestDLFExtensionDenied(t *testing.T) {
	pol := DefaultDLFPolicy()
	_, _, fs := DLFSanitize("crack.exe", pol)
	if !dlfHas(fs, DLFReasonExtensionDenied) {
		t.Fatalf("want exe denied, got %v", fs)
	}
}

func TestDLFControlChar(t *testing.T) {
	pol := DefaultDLFPolicy()
	_, _, fs := DLFSanitize("mo\x00d.jar", pol)
	if !dlfHas(fs, DLFReasonControlChar) {
		t.Fatalf("want control char, got %v", fs)
	}
}
