package main

import "testing"

func bndHas(fs []BNDFinding, method, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason && f.Method == method {
			return true
		}
	}
	return false
}

func TestBNDSafeReadonlyProfile(t *testing.T) {
	pol := DefaultBNDPolicy()
	bindings := []BNDBinding{{
		Name:       "GetProfile",
		Capability: BNDCapability{},
		Guard:      BNDGuard{},
	}}
	safe, _ := BNDAudit(bindings, pol)
	if !safe {
		t.Fatal("pure readonly no-input binding should pass")
	}
}

func TestBNDPathUnvalidated(t *testing.T) {
	pol := DefaultBNDPolicy()
	bindings := []BNDBinding{{
		Name:       "ImportPack",
		Capability: BNDCapability{TakesPath: true, WritesOrDeletes: true},
		Guard:      BNDGuard{PathValidated: false, WriteConfirmed: true, OriginEnforced: true},
	}}
	_, fs := BNDAudit(bindings, pol)
	if !bndHas(fs, "ImportPack", BNDReasonPathNotValidated) {
		t.Fatalf("want path unvalidated, got %v", fs)
	}
}

func TestBNDURLNoSSRF(t *testing.T) {
	pol := DefaultBNDPolicy()
	bindings := []BNDBinding{{
		Name:       "DownloadMod",
		Capability: BNDCapability{TakesURL: true},
		Guard:      BNDGuard{},
	}}
	_, fs := BNDAudit(bindings, pol)
	if !bndHas(fs, "DownloadMod", BNDReasonURLNotValidated) {
		t.Fatalf("want url not validated, got %v", fs)
	}
}

func TestBNDGenericRunCommand(t *testing.T) {
	pol := DefaultBNDPolicy()
	bindings := []BNDBinding{{
		Name:       "RunCommand",
		Capability: BNDCapability{TakesCommandArgs: true, ExecProcess: true, GenericPrimitive: true},
		Guard:      BNDGuard{CommandAllowlist: true, ExecConfirmed: true, OriginEnforced: true},
	}}
	_, fs := BNDAudit(bindings, pol)
	if !bndHas(fs, "RunCommand", BNDReasonGenericPrimitive) {
		t.Fatalf("want generic primitive, got %v", fs)
	}
}

func TestBNDWriteNoConfirm(t *testing.T) {
	pol := DefaultBNDPolicy()
	bindings := []BNDBinding{{
		Name:       "SaveConfig",
		Capability: BNDCapability{TakesPath: true, WritesOrDeletes: true},
		Guard:      BNDGuard{PathValidated: true, OriginEnforced: true},
	}}
	_, fs := BNDAudit(bindings, pol)
	if !bndHas(fs, "SaveConfig", BNDReasonWriteNoConfirm) {
		t.Fatalf("want write no confirm, got %v", fs)
	}
}

func TestBNDExecNoOrigin(t *testing.T) {
	pol := DefaultBNDPolicy()
	bindings := []BNDBinding{{
		Name:       "LaunchGame",
		Capability: BNDCapability{ExecProcess: true, TakesCommandArgs: true},
		Guard:      BNDGuard{CommandAllowlist: true, ExecConfirmed: true},
	}}
	_, fs := BNDAudit(bindings, pol)
	if !bndHas(fs, "LaunchGame", BNDReasonNoOriginBoundary) {
		t.Fatalf("want no origin boundary, got %v", fs)
	}
}

func TestBNDRawBodyUnbounded(t *testing.T) {
	pol := DefaultBNDPolicy()
	bindings := []BNDBinding{{
		Name:       "SubmitCrashBlob",
		Capability: BNDCapability{TakesRawBody: true},
		Guard:      BNDGuard{RawBodyLimited: false},
	}}
	_, fs := BNDAudit(bindings, pol)
	if !bndHas(fs, "SubmitCrashBlob", BNDReasonRawBodyUnbounded) {
		t.Fatalf("want raw body unbounded, got %v", fs)
	}
}

func TestBNDReturnsSensitive(t *testing.T) {
	pol := DefaultBNDPolicy()
	bindings := []BNDBinding{{
		Name:       "GetAccessToken",
		Capability: BNDCapability{ReturnsSensitive: true},
		Guard:      BNDGuard{},
	}}
	_, fs := BNDAudit(bindings, pol)
	if !bndHas(fs, "GetAccessToken", BNDReasonReturnsSensitive) {
		t.Fatalf("want returns sensitive, got %v", fs)
	}
}

func TestBNDSecuredLaunch(t *testing.T) {
	pol := DefaultBNDPolicy()
	bindings := []BNDBinding{{
		Name: "LaunchGame",
		Capability: BNDCapability{
			TakesPath: true, TakesCommandArgs: true, ExecProcess: true,
		},
		Guard: BNDGuard{
			PathValidated: true, CommandAllowlist: true, ExecConfirmed: true, OriginEnforced: true,
		},
	}}
	safe, _ := BNDAudit(bindings, pol)
	if !safe {
		t.Fatal("fully guarded launch should pass")
	}
}
