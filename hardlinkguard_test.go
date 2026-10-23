package main

import "testing"

func TestHLPlainFiles(t *testing.T) {
	ents := []HLFileIdentity{
		{Path: "a.jar", Device: 1, FileID: 10, InsideBase: true},
		{Path: "b.jar", Device: 1, FileID: 11, InsideBase: true},
	}
	r := HLAuditEntries(DefaultHLPolicy(), 1, ents)
	if !r.Safe {
		t.Fatalf("plain files should be safe: %v", r.Findings)
	}
}

func TestHLArchiveHardlinkEntry(t *testing.T) {
	ents := []HLFileIdentity{
		{Path: "x", Device: 1, FileID: 10, IsHardlink: true, InsideBase: true},
	}
	r := HLAuditEntries(DefaultHLPolicy(), 1, ents)
	if !r.HasReason(HLReasonZipHardlinkEntry) {
		t.Fatalf("want archive hardlink entry: %v", r.Findings)
	}
}

func TestHLCrossDevice(t *testing.T) {
	ents := []HLFileIdentity{
		{Path: "a.jar", Device: 2, FileID: 10, InsideBase: true},
	}
	r := HLAuditEntries(DefaultHLPolicy(), 1, ents)
	if !r.HasReason(HLReasonCrossDevice) {
		t.Fatalf("want cross device: %v", r.Findings)
	}
}

func TestHLEscapesBaseOutsideFirst(t *testing.T) {
	// 同一 inode：先在目录外出现（被打包扫描到），再在目录内出现
	ents := []HLFileIdentity{
		{Path: "C:/secrets/token.json", Device: 1, FileID: 777, InsideBase: false},
		{Path: "instance/link.json", Device: 1, FileID: 777, InsideBase: true},
	}
	r := HLAuditEntries(DefaultHLPolicy(), 1, ents)
	if !r.HasReason(HLReasonEscapesBase) {
		t.Fatalf("want escapes base: %v", r.Findings)
	}
}

func TestHLDuplicateInodeInsideFirst(t *testing.T) {
	ents := []HLFileIdentity{
		{Path: "instance/a", Device: 1, FileID: 888, InsideBase: true},
		{Path: "C:/other/b", Device: 1, FileID: 888, InsideBase: false},
	}
	r := HLAuditEntries(DefaultHLPolicy(), 1, ents)
	if !r.HasReason(HLReasonDuplicateInode) {
		t.Fatalf("want duplicate inode: %v", r.Findings)
	}
}

func TestHLDistinctSameFileIDDifferentDevice(t *testing.T) {
	// 相同 FileID 但不同 Device 是不同对象，不得误报
	ents := []HLFileIdentity{
		{Path: "instance/a", Device: 1, FileID: 5, InsideBase: true},
		{Path: "other/b", Device: 2, FileID: 5, InsideBase: false},
	}
	r := HLAuditEntries(DefaultHLPolicy(), 1, ents)
	if r.HasReason(HLReasonEscapesBase) || r.HasReason(HLReasonDuplicateInode) {
		t.Fatalf("cross-device same fileid wrongly linked: %v", r.Findings)
	}
}

func TestHLEmptyPath(t *testing.T) {
	ents := []HLFileIdentity{{Path: "", Device: 1, FileID: 1, InsideBase: true}}
	r := HLAuditEntries(DefaultHLPolicy(), 1, ents)
	if !r.HasReason(HLReasonEmptyPath) {
		t.Fatalf("want empty path: %v", r.Findings)
	}
}

func TestHLHardlinksAllowedByPolicy(t *testing.T) {
	pol := HLPolicy{RejectArchiveHardlinks: false, RequireSameDevice: false}
	ents := []HLFileIdentity{
		{Path: "a", Device: 9, FileID: 1, IsHardlink: true, InsideBase: true},
	}
	r := HLAuditEntries(pol, 0, ents)
	if !r.Safe {
		t.Fatalf("relaxed policy should pass: %v", r.Findings)
	}
}

func TestHLMultipleInsideSameInode(t *testing.T) {
	// 两个目录内硬链接互相指向（都在基内）不算逃逸
	ents := []HLFileIdentity{
		{Path: "instance/a", Device: 1, FileID: 3, IsHardlink: true, InsideBase: true},
		{Path: "instance/b", Device: 1, FileID: 3, IsHardlink: true, InsideBase: true},
	}
	r := HLAuditEntries(DefaultHLPolicy(), 1, ents)
	if r.HasReason(HLReasonEscapesBase) || r.HasReason(HLReasonDuplicateInode) {
		t.Fatalf("inside-only hardlinks wrongly flagged: %v", r.Findings)
	}
}
