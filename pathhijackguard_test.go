package main

import "testing"

func phjHas(fs []PHJFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPHJGoodPath(t *testing.T) {
	pol := DefaultPHJPolicy()
	entries := []PHJPathEntry{
		{Path: `C:\Program Files\Java\jdk\bin`, ContainsJava: true},
		{Path: `C:\Windows\System32`},
	}
	safe, _ := PHJInspectPath(entries, pol)
	if !safe {
		t.Fatal("absolute trusted path should pass")
	}
}

func TestPHJEmptyEntry(t *testing.T) {
	pol := DefaultPHJPolicy()
	entries := []PHJPathEntry{{IsEmpty: true}, {Path: `C:\Windows`}}
	_, fs := PHJInspectPath(entries, pol)
	if !phjHas(fs, PHJReasonEmptyPathEntry) {
		t.Fatalf("want empty entry, got %v", fs)
	}
}

func TestPHJRelativeEntry(t *testing.T) {
	pol := DefaultPHJPolicy()
	entries := []PHJPathEntry{{Path: "tools\\bin", IsRelative: true}}
	_, fs := PHJInspectPath(entries, pol)
	if !phjHas(fs, PHJReasonRelativeEntry) {
		t.Fatalf("want relative entry, got %v", fs)
	}
}

func TestPHJWritableEntry(t *testing.T) {
	pol := DefaultPHJPolicy()
	entries := []PHJPathEntry{{Path: `C:\Users\me\Downloads`, Writable: true}}
	_, fs := PHJInspectPath(entries, pol)
	if !phjHas(fs, PHJReasonWritableEntry) {
		t.Fatalf("want writable entry, got %v", fs)
	}
}

func TestPHJCWDFirst(t *testing.T) {
	pol := DefaultPHJPolicy()
	entries := []PHJPathEntry{{Path: ".", IsCWD: true, IsRelative: true}, {Path: `C:\jdk\bin`}}
	_, fs := PHJInspectPath(entries, pol)
	if !phjHas(fs, PHJReasonCurrentDirFirst) {
		t.Fatalf("want cwd first, got %v", fs)
	}
}

func TestPHJDuplicateJava(t *testing.T) {
	pol := DefaultPHJPolicy()
	entries := []PHJPathEntry{
		{Path: `C:\jdk1\bin`, ContainsJava: true},
		{Path: `C:\jdk2\bin`, ContainsJava: true},
	}
	_, fs := PHJInspectPath(entries, pol)
	if !phjHas(fs, PHJReasonDuplicateJava) {
		t.Fatalf("want duplicate java, got %v", fs)
	}
}

func TestPHJBareCommand(t *testing.T) {
	pol := DefaultPHJPolicy()
	_, fs := PHJInspectExec(PHJExecRequest{Command: "java"}, false, pol)
	if !phjHas(fs, PHJReasonBareCommandName) {
		t.Fatalf("want bare command, got %v", fs)
	}
}

func TestPHJAbsoluteBinary(t *testing.T) {
	pol := DefaultPHJPolicy()
	req := PHJExecRequest{Command: `C:\jdk\bin\java.exe`, ResolvedAbsPath: `C:\jdk\bin\java.exe`}
	safe, _ := PHJInspectExec(req, false, pol)
	if !safe {
		t.Fatal("absolute read-only binary should pass")
	}
}

func TestPHJUnquotedSpaces(t *testing.T) {
	pol := DefaultPHJPolicy()
	req := PHJExecRequest{Command: `C:\Program Files\Java\bin\java.exe`}
	_, fs := PHJInspectExec(req, false, pol)
	if !phjHas(fs, PHJReasonUnquotedSpaces) {
		t.Fatalf("want unquoted spaces, got %v", fs)
	}
}

func TestPHJResolvedWritable(t *testing.T) {
	pol := DefaultPHJPolicy()
	req := PHJExecRequest{
		Command:          `C:\tools\java.exe`,
		ResolvedAbsPath:  `C:\tools\java.exe`,
		ResolvedWritable: true,
	}
	_, fs := PHJInspectExec(req, false, pol)
	if !phjHas(fs, PHJReasonResolvedWritable) {
		t.Fatalf("want resolved writable, got %v", fs)
	}
}

func TestPHJIsAbsolute(t *testing.T) {
	if !phjIsAbsolute(`D:\jdk\bin`) || !phjIsAbsolute("/usr/bin") {
		t.Fatal("absolute not detected")
	}
	if phjIsAbsolute("tools\\bin") {
		t.Fatal("relative misdetected")
	}
}
