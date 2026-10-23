package main

import "testing"

func wpgHas(fs []WPGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func wpgGood() WPGView {
	return WPGView{
		SavesRoot:   `C:\game\.minecraft\saves`,
		WorldDir:    `C:\game\.minecraft\saves\My World`,
		HasLevelDat: true, LevelDatSize: 12345,
	}
}

func TestWPGGood(t *testing.T) {
	safe, _ := WPGValidateWorld(wpgGood(), DefaultWPGPolicy())
	if !safe {
		t.Fatal("normal world dir should pass")
	}
}

func TestWPGEscapesRoot(t *testing.T) {
	v := wpgGood()
	v.WorldDir = `C:\game\.minecraft\versions\1.20`
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonEscapesSavesRoot) {
		t.Fatalf("want escape, got %v", fs)
	}
}

func TestWPGDotDot(t *testing.T) {
	v := wpgGood()
	v.WorldDir = `C:\game\.minecraft\saves\..\..\etc`
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonEscapesSavesRoot) {
		t.Fatalf("want dotdot escape, got %v", fs)
	}
}

func TestWPGSymlink(t *testing.T) {
	v := wpgGood()
	v.IsSymlink = true
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonSymlinkDir) {
		t.Fatalf("want symlink, got %v", fs)
	}
}

func TestWPGRootTarget(t *testing.T) {
	v := wpgGood()
	v.WorldDir = v.SavesRoot
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonTargetsSavesRoot) {
		t.Fatalf("want saves root target, got %v", fs)
	}
}

func TestWPGParentTarget(t *testing.T) {
	v := wpgGood()
	v.WorldDir = `C:\game\.minecraft`
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonTargetsSavesRoot) {
		t.Fatalf("want parent target, got %v", fs)
	}
}

func TestWPGInternalEscape(t *testing.T) {
	v := wpgGood()
	v.InternalRefs = []string{`datapacks\..\..\outside`}
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonInternalEscape) {
		t.Fatalf("want internal escape, got %v", fs)
	}
}

func TestWPGLockBackedUp(t *testing.T) {
	v := wpgGood()
	v.BacksUpLock = true
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonSessionLockCopied) {
		t.Fatalf("want session lock, got %v", fs)
	}
}

func TestWPGMissingLevel(t *testing.T) {
	v := wpgGood()
	v.HasLevelDat = false
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonMissingLevelDat) {
		t.Fatalf("want missing level.dat, got %v", fs)
	}
}

func TestWPGLevelTooSmall(t *testing.T) {
	v := wpgGood()
	v.LevelDatSize = 2
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonLevelDatBadSize) {
		t.Fatalf("want level too small, got %v", fs)
	}
}

func TestWPGLevelTooBig(t *testing.T) {
	v := wpgGood()
	v.LevelDatSize = 100 * 1024 * 1024
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonLevelDatBadSize) {
		t.Fatalf("want level too big, got %v", fs)
	}
}

func TestWPGRestoreOverwrite(t *testing.T) {
	v := wpgGood()
	v.RestoreTargetExists = true
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonOverwriteExisting) {
		t.Fatalf("want overwrite existing, got %v", fs)
	}
}

func TestWPGAbsoluteOutside(t *testing.T) {
	v := wpgGood()
	v.SavesRoot = ""
	v.WorldDir = `D:\other\world`
	_, fs := WPGValidateWorld(v, DefaultWPGPolicy())
	if !wpgHas(fs, WPGReasonAbsoluteWorld) {
		t.Fatalf("want absolute outside, got %v", fs)
	}
}
