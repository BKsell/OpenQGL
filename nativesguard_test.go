package main

import "testing"

func ntvHas(fs []NTVFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestNTVClean(t *testing.T) {
	pol := DefaultNTVPolicy()
	decl := []NTVDeclaredLib{{Name: "lwjgl.dll"}, {Name: "OpenAL.dll"}}
	disk := []NTVOnDiskLib{
		{Name: "lwjgl.dll", RelPath: "lwjgl.dll"},
		{Name: "OpenAL.dll", RelPath: "OpenAL.dll"},
	}
	safe, _ := NTVInspectDir(decl, disk, false, pol)
	if !safe {
		t.Fatal("declared set matching read-only dir should pass")
	}
}

func TestNTVUnexpectedLib(t *testing.T) {
	pol := DefaultNTVPolicy()
	decl := []NTVDeclaredLib{{Name: "lwjgl.dll"}}
	disk := []NTVOnDiskLib{{Name: "lwjgl.dll"}, {Name: "evil.dll"}}
	_, fs := NTVInspectDir(decl, disk, false, pol)
	if !ntvHas(fs, NTVReasonUnexpectedLibrary) {
		t.Fatalf("want unexpected lib, got %v", fs)
	}
}

func TestNTVMissingLib(t *testing.T) {
	pol := DefaultNTVPolicy()
	decl := []NTVDeclaredLib{{Name: "lwjgl.dll"}, {Name: "OpenAL.dll"}}
	disk := []NTVOnDiskLib{{Name: "lwjgl.dll"}}
	_, fs := NTVInspectDir(decl, disk, false, pol)
	if !ntvHas(fs, NTVReasonMissingLibrary) {
		t.Fatalf("want missing, got %v", fs)
	}
}

func TestNTVDuplicateLib(t *testing.T) {
	pol := DefaultNTVPolicy()
	decl := []NTVDeclaredLib{{Name: "lwjgl.dll"}}
	disk := []NTVOnDiskLib{{Name: "lwjgl.dll", RelPath: "a\\lwjgl.dll"},
		{Name: "lwjgl.dll", RelPath: "b\\lwjgl.dll"}}
	_, fs := NTVInspectDir(decl, disk, false, pol)
	if !ntvHas(fs, NTVReasonDuplicateLibrary) {
		t.Fatalf("want duplicate, got %v", fs)
	}
}

func TestNTVWritableFile(t *testing.T) {
	pol := DefaultNTVPolicy()
	decl := []NTVDeclaredLib{{Name: "lwjgl.dll"}}
	disk := []NTVOnDiskLib{{Name: "lwjgl.dll", Writable: true}}
	_, fs := NTVInspectDir(decl, disk, false, pol)
	if !ntvHas(fs, NTVReasonWritableLibrary) {
		t.Fatalf("want writable lib, got %v", fs)
	}
}

func TestNTVWritableDir(t *testing.T) {
	pol := DefaultNTVPolicy()
	_, fs := NTVInspectDir(nil, nil, true, pol)
	if !ntvHas(fs, NTVReasonWritableDir) {
		t.Fatalf("want writable dir, got %v", fs)
	}
}

func TestNTVPathEscape(t *testing.T) {
	pol := DefaultNTVPolicy()
	decl := []NTVDeclaredLib{{Name: "lwjgl.dll"}}
	disk := []NTVOnDiskLib{{Name: "lwjgl.dll", RelPath: "..\\..\\lwjgl.dll"}}
	_, fs := NTVInspectDir(decl, disk, false, pol)
	if !ntvHas(fs, NTVReasonPathEscape) {
		t.Fatalf("want path escape, got %v", fs)
	}
}

func TestNTVBadExtension(t *testing.T) {
	pol := DefaultNTVPolicy()
	decl := []NTVDeclaredLib{{Name: "lwjgl.dll"}}
	// 磁盘上出现 .exe，不在允许库类型
	disk := []NTVOnDiskLib{{Name: "lwjgl.dll"}, {Name: "lwjgl.exe"}}
	_, fs := NTVInspectDir(decl, disk, false, pol)
	if !ntvHas(fs, NTVReasonBadExtension) {
		t.Fatalf("want bad extension, got %v", fs)
	}
}

func TestNTVSymlink(t *testing.T) {
	pol := DefaultNTVPolicy()
	decl := []NTVDeclaredLib{{Name: "lwjgl.dll"}}
	disk := []NTVOnDiskLib{{Name: "lwjgl.dll", IsSymlink: true}}
	_, fs := NTVInspectDir(decl, disk, false, pol)
	if !ntvHas(fs, NTVReasonUnexpectedFileType) {
		t.Fatalf("want symlink, got %v", fs)
	}
}

func TestNTVBareLoad(t *testing.T) {
	pol := DefaultNTVPolicy()
	_, fs := NTVInspectLoad(NTVOnDiskLib{LoadName: "lwjgl", IsLoadReq: true}, pol)
	if !ntvHas(fs, NTVReasonBareLoadName) {
		t.Fatalf("want bare load, got %v", fs)
	}
}

func TestNTVAbsoluteLoad(t *testing.T) {
	pol := DefaultNTVPolicy()
	safe, _ := NTVInspectLoad(NTVOnDiskLib{LoadName: `C:\mc\natives\lwjgl.dll`}, pol)
	if !safe {
		t.Fatal("absolute load path should pass")
	}
}

func TestNTVCaseInsensitiveDup(t *testing.T) {
	pol := DefaultNTVPolicy()
	decl := []NTVDeclaredLib{{Name: "LWJGL.DLL"}}
	disk := []NTVOnDiskLib{{Name: "lwjgl.dll"}}
	safe, _ := NTVInspectDir(decl, disk, false, pol)
	if !safe {
		t.Fatal("case-insensitive name should match declared on windows")
	}
}
