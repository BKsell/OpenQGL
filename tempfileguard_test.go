package main

import "testing"

func tfgHas(fs []TFGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func tfgGood() TFGView {
	return TFGView{
		NamePattern: "dl-*.tmp", Dir: "C:\\Users\\me\\AppData\\Local\\Temp",
		ModePerm: 0600, ExclusiveCreate: true, CleanupScheduled: true,
	}
}

func TestTFGGood(t *testing.T) {
	pol := DefaultTFGPolicy()
	safe, _ := TFGEvaluate(tfgGood(), pol)
	if !safe {
		t.Fatal("random exclusive 0600 cleaned temp should pass")
	}
}

func TestTFGPredictable(t *testing.T) {
	pol := DefaultTFGPolicy()
	v := tfgGood()
	v.NamePattern = "launcher-tmp.zip"
	_, fs := TFGEvaluate(v, pol)
	if !tfgHas(fs, TFGReasonPredictableName) {
		t.Fatalf("want predictable, got %v", fs)
	}
}

func TestTFGSharedDir(t *testing.T) {
	pol := DefaultTFGPolicy()
	v := tfgGood()
	v.SharedOrWorldWritable = true
	_, fs := TFGEvaluate(v, pol)
	if !tfgHas(fs, TFGReasonSharedDir) {
		t.Fatalf("want shared dir, got %v", fs)
	}
}

func TestTFGWorldPermissive(t *testing.T) {
	pol := DefaultTFGPolicy()
	v := tfgGood()
	v.ModePerm = 0644
	_, fs := TFGEvaluate(v, pol)
	if !tfgHas(fs, TFGReasonOverlyPermissive) {
		t.Fatalf("want permissive, got %v", fs)
	}
}

func TestTFGNoExclusive(t *testing.T) {
	pol := DefaultTFGPolicy()
	v := tfgGood()
	v.ExclusiveCreate = false
	_, fs := TFGEvaluate(v, pol)
	if !tfgHas(fs, TFGReasonNoExclusiveCreate) {
		t.Fatalf("want no exclusive, got %v", fs)
	}
}

func TestTFGNotCleaned(t *testing.T) {
	pol := DefaultTFGPolicy()
	v := tfgGood()
	v.CleanupScheduled = false
	_, fs := TFGEvaluate(v, pol)
	if !tfgHas(fs, TFGReasonNotCleanedUp) {
		t.Fatalf("want not cleaned, got %v", fs)
	}
}

func TestTFGSensitiveShared(t *testing.T) {
	pol := DefaultTFGPolicy()
	v := tfgGood()
	v.HoldsSensitive = true
	v.SharedOrWorldWritable = true
	_, fs := TFGEvaluate(v, pol)
	if !tfgHas(fs, TFGReasonSensitiveContent) {
		t.Fatalf("want sensitive in shared, got %v", fs)
	}
}

func TestTFGSensitiveGroupRead(t *testing.T) {
	pol := DefaultTFGPolicy()
	v := tfgGood()
	v.HoldsSensitive = true
	v.ModePerm = 0640 // group readable, exceeds 0600
	_, fs := TFGEvaluate(v, pol)
	if !tfgHas(fs, TFGReasonOverlyPermissive) {
		t.Fatalf("want sensitive group read flagged, got %v", fs)
	}
}

func TestTFGUNC(t *testing.T) {
	pol := DefaultTFGPolicy()
	v := tfgGood()
	v.TempDirUNC = true
	_, fs := TFGEvaluate(v, pol)
	if !tfgHas(fs, TFGReasonRemoteTemp) {
		t.Fatalf("want unc temp, got %v", fs)
	}
}

func TestTFGSetuidBit(t *testing.T) {
	pol := DefaultTFGPolicy()
	v := tfgGood()
	v.ModePerm = 04600
	_, fs := TFGEvaluate(v, pol)
	if !tfgHas(fs, TFGReasonOverlyPermissive) {
		t.Fatalf("want high bit flagged, got %v", fs)
	}
}
