package main

import "testing"

func TestAWHealthySequence(t *testing.T) {
	evs := []AWEvent{
		{Step: AWStepCreateTemp, TempPath: `C:\cfg\.accounts.tmp1`, TargetDir: `C:\cfg`,
			TempVolume: "C:", DirVolume: "C:", NameRandom: true},
		{Step: AWStepWrite},
		{Step: AWStepFileSync},
		{Step: AWStepRename, DestPath: `C:\cfg\accounts.json`, WantPath: `C:\cfg\accounts.json`},
		{Step: AWStepDirSync},
	}
	if safe, fs := AWAudit(evs); !safe {
		t.Fatalf("proper atomic write should pass: %v", fs)
	}
}

func TestAWCrossDevice(t *testing.T) {
	evs := []AWEvent{
		{Step: AWStepCreateTemp, TempPath: `D:\tmp\a.tmp`, TargetDir: `C:\cfg`,
			TempVolume: "D:", DirVolume: "C:", NameRandom: true},
		{Step: AWStepFileSync},
		{Step: AWStepRename, DestPath: `C:\cfg\a.json`, WantPath: `C:\cfg\a.json`},
	}
	_, fs := AWAudit(evs)
	if !AWHas(fs, AWReasonTempCrossDevice) {
		t.Fatalf("cross-volume temp must flag: %v", fs)
	}
}

func TestAWPredictableName(t *testing.T) {
	evs := []AWEvent{
		{Step: AWStepCreateTemp, TempPath: `C:\cfg\temp.dat`, TargetDir: `C:\cfg`,
			TempVolume: "C:", DirVolume: "C:", NameRandom: false},
		{Step: AWStepFileSync},
		{Step: AWStepRename, DestPath: `C:\cfg\a.json`, WantPath: `C:\cfg\a.json`},
	}
	_, fs := AWAudit(evs)
	if !AWHas(fs, AWReasonPredictableName) {
		t.Fatalf("fixed temp name must flag: %v", fs)
	}
}

func TestAWRenameBeforeSync(t *testing.T) {
	evs := []AWEvent{
		{Step: AWStepCreateTemp, TempPath: `C:\cfg\.a.tmp`, TargetDir: `C:\cfg`,
			TempVolume: "C:", DirVolume: "C:", NameRandom: true},
		{Step: AWStepRename, DestPath: `C:\cfg\a.json`, WantPath: `C:\cfg\a.json`},
	}
	_, fs := AWAudit(evs)
	if !AWHas(fs, AWReasonMissingDataSync) {
		t.Fatalf("rename before fsync must flag: %v", fs)
	}
}

func TestAWNoDirSync(t *testing.T) {
	evs := []AWEvent{
		{Step: AWStepCreateTemp, TempPath: `C:\cfg\.a.tmp`, TargetDir: `C:\cfg`,
			TempVolume: "C:", DirVolume: "C:", NameRandom: true},
		{Step: AWStepFileSync},
		{Step: AWStepRename, DestPath: `C:\cfg\a.json`, WantPath: `C:\cfg\a.json`},
	}
	_, fs := AWAudit(evs)
	if !AWHas(fs, AWReasonMissingDirSync) {
		t.Fatalf("missing parent dir fsync must flag: %v", fs)
	}
}

func TestAWWrongFinalPath(t *testing.T) {
	evs := []AWEvent{
		{Step: AWStepCreateTemp, TempPath: `C:\cfg\.a.tmp`, TargetDir: `C:\cfg`,
			TempVolume: "C:", DirVolume: "C:", NameRandom: true},
		{Step: AWStepFileSync},
		{Step: AWStepRename, DestPath: `C:\other\a.json`, WantPath: `C:\cfg\a.json`},
		{Step: AWStepDirSync},
	}
	_, fs := AWAudit(evs)
	if !AWHas(fs, AWReasonWrongFinalPath) {
		t.Fatalf("rename to wrong destination must flag: %v", fs)
	}
}

func TestAWTempLeftoverOnAbort(t *testing.T) {
	evs := []AWEvent{
		{Step: AWStepCreateTemp, TempPath: `C:\cfg\.a.tmp`, TargetDir: `C:\cfg`,
			TempVolume: "C:", DirVolume: "C:", NameRandom: true},
		{Step: AWStepWrite},
		// 未 rename、未 cleanup
	}
	_, fs := AWAudit(evs)
	if !AWHas(fs, AWReasonTempLeftover) {
		t.Fatalf("aborted write without cleanup must flag: %v", fs)
	}
}

func TestAWTempOutsideDir(t *testing.T) {
	evs := []AWEvent{
		{Step: AWStepCreateTemp, TempPath: `C:\windows\temp\a.tmp`, TargetDir: `C:\cfg`,
			TempVolume: "C:", DirVolume: "C:", NameRandom: true},
	}
	_, fs := AWAudit(evs)
	if !AWHas(fs, AWReasonTempNotInDir) {
		t.Fatalf("temp outside target dir must flag: %v", fs)
	}
}
