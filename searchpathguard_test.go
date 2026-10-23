package main

import "testing"

func spCfg() SPConfig {
	return SPConfig{
		PathEntries: []string{
			`c:\program files\java\jdk\bin`,
			`c:\windows\system32`,
		},
		WritableEntries: map[string]bool{},
		TrustedRoots: map[string]bool{
			`c:\program files\java`: true,
			`c:\windows`:            true,
		},
	}
}

func TestSPHealthy(t *testing.T) {
	cfg := spCfg()
	if safe, _ := SPAuditPath(cfg); !safe {
		t.Fatal("trusted-first PATH should be clean")
	}
	if safe, _ := SPResolve(cfg, `c:\program files\java\jdk\bin`, ".exe"); !safe {
		t.Fatal("java under trusted root with .exe should resolve safely")
	}
}

func TestSPEmptyCWDComponent(t *testing.T) {
	cfg := spCfg()
	cfg.PathEntries = []string{"", `.`, `c:\windows\system32`}
	_, fs := SPAuditPath(cfg)
	if !SPHasReason(fs, SPReasonEmptyPathComponent) {
		t.Fatalf("empty/`.` component before system must flag: %v", fs)
	}
}

func TestSPWritableDirFirst(t *testing.T) {
	cfg := spCfg()
	cfg.PathEntries = []string{`c:\users\victim\downloads`, `c:\windows\system32`}
	cfg.WritableEntries[`c:\users\victim\downloads`] = true
	_, fs := SPAuditPath(cfg)
	if !SPHasReason(fs, SPReasonWritableDirFirst) {
		t.Fatalf("writable dir before system must flag: %v", fs)
	}
}

func TestSPWritableDirAfterSystemOK(t *testing.T) {
	cfg := spCfg()
	cfg.PathEntries = []string{`c:\windows\system32`, `c:\dev\bin`}
	cfg.WritableEntries[`c:\dev\bin`] = true
	if safe, _ := SPAuditPath(cfg); !safe {
		t.Fatal("writable dir after a trusted system dir should not trip order warning")
	}
}

func TestSPResolvedScript(t *testing.T) {
	cfg := spCfg()
	_, fs := SPResolve(cfg, `c:\windows\system32`, ".cmd")
	if !SPHasReason(fs, SPReasonUnsafeExtension) {
		t.Fatalf("resolving java to .cmd must flag: %v", fs)
	}
}

func TestSPResolvedWritableLocation(t *testing.T) {
	cfg := spCfg()
	cfg.WritableEntries[`c:\temp`] = true
	_, fs := SPResolve(cfg, `c:\temp`, ".exe")
	if !SPHasReason(fs, SPReasonCandidateWritable) {
		t.Fatalf("binary in user-writable dir must flag: %v", fs)
	}
	if !SPHasReason(fs, SPReasonOutsideSystemRoot) {
		t.Fatalf("binary outside trusted roots must flag: %v", fs)
	}
}

func TestSPNoTrustedRootsSkipsRootCheck(t *testing.T) {
	cfg := SPConfig{}
	if safe, _ := SPResolve(cfg, `c:\whatever`, ".exe"); !safe {
		t.Fatal("without configured trusted roots, root check should not apply")
	}
}
