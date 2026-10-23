package main

import "testing"

func TestFTCClassifyKnownExecutable(t *testing.T) {
	cases := []string{".exe", ".dll", ".scr", ".com", ".msi", ".sys", ".bat", ".cmd", ".ps1"}
	for _, e := range cases {
		if FTCClassifyExt(e) != FTCClassExecutable {
			t.Fatalf("%s must classify executable", e)
		}
	}
}

func TestFTCClassifyScript(t *testing.T) {
	cases := []string{".js", ".py", ".rb", ".sh", ".lua", ".ahk", ".vbs"}
	for _, e := range cases {
		if FTCClassifyExt(e) != FTCClassScript {
			t.Fatalf("%s must classify script", e)
		}
	}
}

func TestFTCClassifyShortcut(t *testing.T) {
	cases := []string{".lnk", ".url", ".desktop", ".scf", ".appref-ms"}
	for _, e := range cases {
		if FTCClassifyExt(e) != FTCClassShortcut {
			t.Fatalf("%s must classify shortcut", e)
		}
	}
}

func TestFTCClassifyMacroDoc(t *testing.T) {
	cases := []string{".docm", ".xlsm", ".pptm", ".doc", ".xls", ".rtf"}
	for _, e := range cases {
		if FTCClassifyExt(e) != FTCClassMacro {
			t.Fatalf("%s must classify macrodoc", e)
		}
	}
}

func TestFTCClassifyArchive(t *testing.T) {
	cases := []string{".zip", ".7z", ".rar", ".tar", ".gz", ".mrpack", ".mcworld"}
	for _, e := range cases {
		if FTCClassifyExt(e) != FTCClassArchive {
			t.Fatalf("%s must classify archive", e)
		}
	}
}

func TestFTCClassifySafeData(t *testing.T) {
	cases := []string{".png", ".jpg", ".json", ".txt", ".pdf", ".mp3", ".woff2"}
	for _, e := range cases {
		if FTCClassifyExt(e) != FTCClassSafe {
			t.Fatalf("%s must classify safe", e)
		}
	}
}

func TestFTCClassifyUnknown(t *testing.T) {
	if FTCClassifyExt(".zzz-not-real") != "" {
		t.Fatal("unknown extension must classify empty")
	}
}

func TestFTCLastExtCases(t *testing.T) {
	pairs := [][2]string{
		{"photo.png", ".png"},
		{"PHOTO.PNG", ".png"},
		{"a.b.c.jar", ".jar"},
		{"noext", ""},
		{".hidden", ".hidden"},
		{"dir/x.TXT", ".txt"},
	}
	for _, p := range pairs {
		if got := FTCLastExt(p[0]); got != p[1] {
			t.Fatalf("LastExt(%q)=%q want %q", p[0], got, p[1])
		}
	}
}

func TestFTCBaseName(t *testing.T) {
	if FTCBaseName("a/b/c.txt") != "c.txt" {
		t.Fatal("forward slash basename")
	}
	if FTCBaseName(`a\b\c.txt`) != "c.txt" {
		t.Fatal("backslash basename")
	}
	if FTCBaseName("plain") != "plain" {
		t.Fatal("plain basename")
	}
}

func TestFTCStripAllExts(t *testing.T) {
	stem, n := FTCStripAllExts("invoice.pdf.exe")
	if stem != "invoice" || n != 2 {
		t.Fatalf("got stem=%q n=%d", stem, n)
	}
	stem2, n2 := FTCStripAllExts("photo")
	if stem2 != "photo" || n2 != 0 {
		t.Fatal("no extension")
	}
}

func TestFTCAuditExecutableFlagged(t *testing.T) {
	r := FTCAuditName("installer.exe")
	if !FTCHas(r, FTCReasonExecutableExt) {
		t.Fatal("exe must be flagged executable")
	}
	if r.Safe {
		t.Fatal("exe must not be safe")
	}
}

func TestFTCAuditDoubleExtension(t *testing.T) {
	r := FTCAuditName("invoice.pdf.exe")
	if !FTCHas(r, FTCReasonDoubleExtension) {
		t.Fatal("double extension must be flagged")
	}
	if !FTCHas(r, FTCReasonExecutableExt) {
		t.Fatal("final exe still flagged")
	}
}

func TestFTCAuditReservedDevice(t *testing.T) {
	for _, n := range []string{"CON.txt", "nul", "LPT1.log", "Com1.dat"} {
		r := FTCAuditName(n)
		if !FTCHas(r, FTCReasonReservedDeviceName) {
			t.Fatalf("%s must hit reserved device", n)
		}
	}
}

func TestFTCAuditNonReservedSimilarName(t *testing.T) {
	// console.txt 的主干是 console，不是 con
	r := FTCAuditName("console.txt")
	if FTCHas(r, FTCReasonReservedDeviceName) {
		t.Fatal("console must not be reserved CON")
	}
}

func TestFTCAuditTrailingDotSpace(t *testing.T) {
	if !FTCHas(FTCAuditName("evil.exe."), FTCReasonTrailingDotSpace) {
		t.Fatal("trailing dot")
	}
	if !FTCHas(FTCAuditName("evil.exe "), FTCReasonTrailingDotSpace) {
		t.Fatal("trailing space")
	}
}

func TestFTCAuditControlChar(t *testing.T) {
	r := FTCAuditName("a\x00b.txt")
	if !FTCHas(r, FTCReasonControlCharacter) {
		t.Fatal("NUL char must be flagged")
	}
}

func TestFTCAuditPathSeparatorRejected(t *testing.T) {
	r := FTCAuditName("sub/dir/file.png")
	if !FTCHas(r, FTCReasonPathSeparator) {
		t.Fatal("embedded slash in name component must be flagged")
	}
}

func TestFTCAuditAdsColon(t *testing.T) {
	if !FTCHas(FTCAuditName("safe.txt:evil"), FTCReasonAdsColon) {
		t.Fatal("ADS colon must be flagged")
	}
}

func TestFTCAuditWildcard(t *testing.T) {
	if !FTCHas(FTCAuditName("a*.txt"), FTCReasonWildcard) {
		t.Fatal("asterisk wildcard")
	}
	if !FTCHas(FTCAuditName("a?.txt"), FTCReasonWildcard) {
		t.Fatal("question wildcard")
	}
}

func TestFTCAuditEmpty(t *testing.T) {
	r := FTCAuditName("")
	if !FTCHas(r, FTCReasonEmptyName) || r.Safe {
		t.Fatal("empty name unsafe")
	}
}

func TestFTCAuditSafeDataFile(t *testing.T) {
	r := FTCAuditName("screenshot.png")
	if !r.Safe {
		t.Fatalf("plain png should be safe, findings=%v", r.Findings)
	}
}

func TestFTCAuditCaseInsensitive(t *testing.T) {
	r := FTCAuditName("SCRIPT.JS")
	if !FTCHas(r, FTCReasonScriptExt) {
		t.Fatal("uppercase .JS must still classify script")
	}
}

func TestFTCCheckMimeConsistent(t *testing.T) {
	ok, _ := FTCCheckMime("a.png", "image/png")
	if !ok {
		t.Fatal("png/png consistent")
	}
}

func TestFTCCheckMimeOctetStreamAllowed(t *testing.T) {
	ok, _ := FTCCheckMime("a.zip", "application/octet-stream")
	if !ok {
		t.Fatal("octet-stream treated as non-contradictory")
	}
}

func TestFTCCheckMimeMismatch(t *testing.T) {
	ok, want := FTCCheckMime("a.png", "text/html")
	if ok || want != "image/png" {
		t.Fatal("png declared text/html must mismatch")
	}
}

func TestFTCCheckMimeNoDeclaration(t *testing.T) {
	ok, want := FTCCheckMime("a.json", "")
	if !ok || want != "application/json" {
		t.Fatal("empty declaration not a contradiction, expected returned")
	}
}

func TestFTCCheckMimeUnknownExt(t *testing.T) {
	ok, _ := FTCCheckMime("a.zzz", "anything/here")
	if !ok {
		t.Fatal("unknown ext cannot be contradicted")
	}
}

func TestFTCLowerAscii(t *testing.T) {
	if FTCLower("AbC123.X") != "abc123.x" {
		t.Fatal("ascii lower")
	}
}

func TestFTCContainsString(t *testing.T) {
	if !FTCContainsString([]string{".a", ".b"}, ".b") {
		t.Fatal("present")
	}
	if FTCContainsString([]string{".a"}, ".c") {
		t.Fatal("absent")
	}
}
