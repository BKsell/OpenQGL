package main

import "testing"

func tarHasReason(fs []TarFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestTarCleanJoinSafe(t *testing.T) {
	cases := map[string]string{
		"mods/a.jar":           "mods/a.jar",
		"config/sub/../x.toml": "config/x.toml",
		"a/b/c/":               "a/b/c",
		"./libraries/foo.dll":  "libraries/foo.dll",
	}
	for in, want := range cases {
		got, escapes, reason := TarCleanJoin(in)
		if escapes {
			t.Fatalf("%s unexpectedly escapes: %s", in, reason)
		}
		if got != want {
			t.Fatalf("%s cleaned=%q want %q", in, got, want)
		}
	}
}

func TestTarTraversal(t *testing.T) {
	bad := []string{
		"../../../etc/passwd",
		"a/../../b.jar",
		"/etc/passwd",
		"\\..\\windows\\system32\\x",
	}
	pol := DefaultTarPolicy()
	for _, n := range bad {
		f := TarEvaluateEntry(TarEntry{Name: n, Typeflag: tarTypeReg}, pol)
		if len(f) == 0 {
			t.Fatalf("%s must be rejected", n)
		}
	}
}

func TestTarWindowsDriveAndUNC(t *testing.T) {
	pol := DefaultTarPolicy()
	if f := TarEvaluateEntry(TarEntry{Name: "C:\\evil.dll", Typeflag: tarTypeReg}, pol);
		!tarHasReason(f, TARReasonWindowsDrive) {
		t.Fatal("drive path must be flagged")
	}
	if f := TarEvaluateEntry(TarEntry{Name: "\\\\server\\share\\x", Typeflag: tarTypeReg}, pol);
		!tarHasReason(f, TARReasonUNC) && !tarHasReason(f, TARReasonAbsolute) {
		t.Fatal("UNC path must be flagged")
	}
}

func TestTarLinkEntries(t *testing.T) {
	pol := DefaultTarPolicy()
	if f := TarEvaluateEntry(TarEntry{Name: "link", Typeflag: tarTypeSymlink, Linkname: "inside"}, pol);
		!tarHasReason(f, TARReasonSymlink) {
		t.Fatal("symlink entry must be rejected")
	}
	if f := TarEvaluateEntry(TarEntry{Name: "hard", Typeflag: tarTypeLink, Linkname: "a.jar"}, pol);
		!tarHasReason(f, TARReasonHardlink) {
		t.Fatal("hardlink entry must be rejected")
	}
}

func TestTarLinkTargetEscape(t *testing.T) {
	esc := []string{"/etc/passwd", "../../../root/.ssh/id_rsa", "C:\\Windows\\x", "\\\\s\\share"}
	for _, l := range esc {
		if !tarLinkTargetEscapes(l) {
			t.Fatalf("link target %q must be considered escaping", l)
		}
	}
	ok := []string{"mods/a.jar", "a/../b", "./config/x"}
	for _, l := range ok {
		if tarLinkTargetEscapes(l) {
			t.Fatalf("link target %q should stay inside root", l)
		}
	}
}

func TestTarSpecialFiles(t *testing.T) {
	pol := DefaultTarPolicy()
	for _, flag := range []byte{tarTypeChar, tarTypeBlock, tarTypeFifo} {
		if f := TarEvaluateEntry(TarEntry{Name: "x", Typeflag: flag}, pol);
			!tarHasReason(f, TARReasonDeviceEntry) {
			t.Fatalf("typeflag %d must be rejected", flag)
		}
	}
}

func TestTarReservedNames(t *testing.T) {
	pol := DefaultTarPolicy()
	if f := TarEvaluateEntry(TarEntry{Name: "CON.txt", Typeflag: tarTypeReg}, pol);
		!tarHasReason(f, TARReasonReservedName) {
		t.Fatal("CON.txt must be flagged")
	}
	if f := TarEvaluateEntry(TarEntry{Name: "LPT1", Typeflag: tarTypeReg}, pol);
		!tarHasReason(f, TARReasonReservedName) {
		t.Fatal("LPT1 must be flagged")
	}
}

func TestTarControlAndEmpty(t *testing.T) {
	pol := DefaultTarPolicy()
	if f := TarEvaluateEntry(TarEntry{Name: "a\x00b", Typeflag: tarTypeReg}, pol);
		!tarHasReason(f, TARReasonControlByte) {
		t.Fatal("NUL byte in name must be flagged")
	}
	if f := TarEvaluateEntry(TarEntry{Name: "", Typeflag: tarTypeReg}, pol);
		!tarHasReason(f, TARReasonEmptyName) {
		t.Fatal("empty name must be flagged")
	}
}

func TestTarIsSafe(t *testing.T) {
	if !TarIsSafe(TarEntry{Name: "mods/sodium.jar", Typeflag: tarTypeReg}) {
		t.Fatal("normal file must be safe")
	}
	if TarIsSafe(TarEntry{Name: "../escape.jar", Typeflag: tarTypeReg}) {
		t.Fatal("traversal must not be safe")
	}
}
