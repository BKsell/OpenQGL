package main

import "testing"

func tcuHas(fs []TCUFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestTCUSafeHandleFlow(t *testing.T) {
	steps := []TCUStep{
		{Kind: "openat", TargetPath: "/safe/dir", HandleID: "h1", FollowsLinks: false},
	}
	// 单步打开且不跟随链接，无检查-使用分裂
	safe, _ := TCUAudit(steps)
	if !safe {
		t.Fatal("single handle-based open should pass")
	}
}

func TestTCUStatThenOpenByPath(t *testing.T) {
	steps := []TCUStep{
		{Kind: "stat", TargetPath: "C:\\game\\java.exe", HandleID: ""},
		{Kind: "open", TargetPath: "C:\\game\\java.exe", HandleID: "", FollowsLinks: false},
	}
	_, fs := TCUAudit(steps)
	if !tcuHas(fs, TCUReasonSplitStatOpen) {
		t.Fatalf("want split stat/open, got %v", fs)
	}
}

func TestTCUSymlinkFollow(t *testing.T) {
	steps := []TCUStep{
		{Kind: "open", TargetPath: "libjli.dll", HandleID: "h1", FollowsLinks: true},
	}
	_, fs := TCUAudit(steps)
	if !tcuHas(fs, TCUReasonNoNoFollow) {
		t.Fatalf("want nofollow, got %v", fs)
	}
}

func TestTCUAccessThenCreate(t *testing.T) {
	steps := []TCUStep{
		{Kind: "access", TargetPath: "config.json", HandleID: ""},
		{Kind: "create", TargetPath: "config.json", HandleID: "", FollowsLinks: false},
	}
	_, fs := TCUAudit(steps)
	if !tcuHas(fs, TCUReasonExistThenCreate) {
		t.Fatalf("want access-then-create, got %v", fs)
	}
}

func TestTCUVerifyThenExecReopen(t *testing.T) {
	steps := []TCUStep{
		{Kind: "verify", TargetPath: "javaw.exe", HandleID: "hv"},
		{Kind: "exec", TargetPath: "javaw.exe", HandleID: "other"},
	}
	_, fs := TCUAudit(steps)
	if !tcuHas(fs, TCUReasonVerifyThenExecStale) {
		t.Fatalf("want verify then exec stale, got %v", fs)
	}
}

func TestTCUVerifyHandleSame(t *testing.T) {
	steps := []TCUStep{
		{Kind: "verify", TargetPath: "javaw.exe", HandleID: "hv"},
		{Kind: "exec", TargetPath: "javaw.exe", HandleID: "hv"},
	}
	safe, _ := TCUAudit(steps)
	if !safe {
		t.Fatal("same-handle verify+exec should pass")
	}
}

func TestTCUExtractRace(t *testing.T) {
	steps := []TCUStep{
		{Kind: "extract", TargetPath: "out/mods/x.jar", HandleID: "", FollowsLinks: false},
	}
	_, fs := TCUAudit(steps)
	if !tcuHas(fs, TCUReasonZipEntryRace) {
		t.Fatalf("want extract race, got %v", fs)
	}
}

func TestTCUTraversalStringRecheck(t *testing.T) {
	steps := []TCUStep{
		{Kind: "stat", TargetPath: "out/../secret", HandleID: ""},
	}
	_, fs := TCUAudit(steps)
	if !tcuHas(fs, TCUReasonPathRecheckedByString) {
		t.Fatalf("want string recheck, got %v", fs)
	}
}
