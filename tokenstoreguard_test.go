package main

import "testing"

func tksHas(fs []TKSFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestTKSSecureProtected(t *testing.T) {
	pol := DefaultTKSPolicy()
	site := TKSSiteView{
		Path:        `C:\Users\me\.openqgl\auth.dat`,
		OSProtected: true,
		PermBits:    0o600,
		HoldsAccess: true,
	}
	safe, _ := TKSEvaluate(site, pol)
	if !safe {
		t.Fatal("os-protected user-scoped store should pass")
	}
}

func TestTKSPlaintextNoProtection(t *testing.T) {
	pol := DefaultTKSPolicy()
	site := TKSSiteView{
		Path:          `C:\Users\me\.openqgl\auth.json`,
		ContainsToken: true,
		PermBits:      0o600,
	}
	_, fs := TKSEvaluate(site, pol)
	if !tksHas(fs, TKSReasonPlaintextToken) {
		t.Fatalf("want plaintext, got %v", fs)
	}
	if !tksHas(fs, TKSReasonNoOSProtection) {
		t.Fatalf("want no os protection, got %v", fs)
	}
}

func TestTKSWorldReadable(t *testing.T) {
	pol := DefaultTKSPolicy()
	site := TKSSiteView{Path: "/home/me/a", PermBits: 0o644, OSProtected: true}
	_, fs := TKSEvaluate(site, pol)
	if !tksHas(fs, TKSReasonWorldReadable) {
		t.Fatalf("want world readable, got %v", fs)
	}
}

func TestTKSWorldWritable(t *testing.T) {
	pol := DefaultTKSPolicy()
	site := TKSSiteView{Path: "/home/me/a", PermBits: 0o666, OSProtected: true}
	_, fs := TKSEvaluate(site, pol)
	if !tksHas(fs, TKSReasonWorldWritable) {
		t.Fatalf("want world writable, got %v", fs)
	}
}

func TestTKSSharedTemp(t *testing.T) {
	pol := DefaultTKSPolicy()
	site := TKSSiteView{Path: `C:\ProgramData\launcher\token.json`, InSharedOrTemp: true, OSProtected: true}
	_, fs := TKSEvaluate(site, pol)
	if !tksHas(fs, TKSReasonSharedOrTempLocation) {
		t.Fatalf("want shared/temp, got %v", fs)
	}
}

func TestTKSBackupCopy(t *testing.T) {
	pol := DefaultTKSPolicy()
	site := TKSSiteView{Path: `C:\Users\me\.openqgl\auth.json.bak`, OSProtected: true}
	_, fs := TKSEvaluate(site, pol)
	if !tksHas(fs, TKSReasonBackupCopyLeak) {
		t.Fatalf("want backup copy, got %v", fs)
	}
}

func TestTKSRefreshAlongside(t *testing.T) {
	pol := DefaultTKSPolicy()
	site := TKSSiteView{
		Path:          `C:\Users\me\.openqgl\auth.dat`,
		ContainsToken: true,
		OSProtected:   true,
		HoldsAccess:   true,
		HoldsRefresh:  true,
	}
	_, fs := TKSEvaluate(site, pol)
	if !tksHas(fs, TKSReasonRefreshAlongside) {
		t.Fatalf("want refresh alongside, got %v", fs)
	}
}

func TestTKSSensitiveFilename(t *testing.T) {
	pol := DefaultTKSPolicy()
	site := TKSSiteView{Path: `C:\Users\me\access_token.txt`, OSProtected: true}
	_, fs := TKSEvaluate(site, pol)
	if !tksHas(fs, TKSReasonSensitiveInFilename) {
		t.Fatalf("want sensitive filename, got %v", fs)
	}
}

func TestTKSCrashDump(t *testing.T) {
	pol := DefaultTKSPolicy()
	site := TKSSiteView{Path: `C:\tmp\hs_err_pid1234.log`, OSProtected: true}
	_, fs := TKSEvaluate(site, pol)
	if !tksHas(fs, TKSReasonBackupCopyLeak) {
		t.Fatalf("want crash/backup, got %v", fs)
	}
}

func TestTKSPermString(t *testing.T) {
	if tksPermString(0o644) != "0644" {
		t.Fatalf("perm string wrong %s", tksPermString(0o644))
	}
}

func TestTKSPermissiveDisabled(t *testing.T) {
	pol := DefaultTKSPolicy()
	pol.RequireOSProtection = false
	pol.ForbidRefreshAlongside = false
	site := TKSSiteView{
		Path:          `C:\Users\me\.openqgl\auth.dat`,
		ContainsToken: true,
		PermBits:      0o600,
		HoldsAccess:   true,
		HoldsRefresh:  true,
	}
	safe, _ := TKSEvaluate(site, pol)
	if !safe {
		t.Fatal("relaxed policy should pass for protected-less 0600 store")
	}
}
