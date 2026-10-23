package main

import "testing"

func aigHas(fs []AIGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func aigHash() string {
	return "0123456789abcdef0123456789abcdef01234567"
}

func TestAIGGood(t *testing.T) {
	h := aigHash()
	v := AIGIndexView{
		DeclaredTotal: 100 + 200,
		Entries: []AIGEntry{
			{Name: "minecraft/sounds/a.ogg", Object: AIGObject{Hash: h, Size: 100,
				StoredPath: "objects/01/" + h}},
			{Name: "minecraft/lang/en_us.json", Object: AIGObject{Hash: h, Size: 200}},
		},
	}
	safe, _ := AIGValidate(v)
	if !safe {
		t.Fatal("consistent index should pass")
	}
}

func TestAIGPathHashMismatch(t *testing.T) {
	h := aigHash()
	v := AIGIndexView{Entries: []AIGEntry{
		{Name: "a.ogg", Object: AIGObject{Hash: h, Size: 10, StoredPath: "objects/ff/" + h}},
	}}
	_, fs := AIGValidate(v)
	if !aigHas(fs, AIGReasonPathHashMismatch) {
		t.Fatalf("want path/hash mismatch, got %v", fs)
	}
}

func TestAIGBadHashLen(t *testing.T) {
	v := AIGIndexView{Entries: []AIGEntry{
		{Name: "a.ogg", Object: AIGObject{Hash: "abc", Size: 10}},
	}}
	_, fs := AIGValidate(v)
	if !aigHas(fs, AIGReasonBadObjectHashLen) {
		t.Fatalf("want bad hash len, got %v", fs)
	}
}

func TestAIGBadHashHex(t *testing.T) {
	v := AIGIndexView{Entries: []AIGEntry{
		{Name: "a.ogg", Object: AIGObject{Hash: "zz23456789abcdef0123456789abcdef01234567", Size: 10}},
	}}
	_, fs := AIGValidate(v)
	if !aigHas(fs, AIGReasonBadObjectHashHex) {
		t.Fatalf("want non-hex hash, got %v", fs)
	}
}

func TestAIGTraversal(t *testing.T) {
	h := aigHash()
	v := AIGIndexView{Entries: []AIGEntry{
		{Name: "../../../Windows/x.ogg", Object: AIGObject{Hash: h, Size: 10}},
	}}
	_, fs := AIGValidate(v)
	if !aigHas(fs, AIGReasonTraversalName) {
		t.Fatalf("want traversal name, got %v", fs)
	}
}

func TestAIGAbsolute(t *testing.T) {
	h := aigHash()
	v := AIGIndexView{Entries: []AIGEntry{
		{Name: "/etc/x.ogg", Object: AIGObject{Hash: h, Size: 10}},
	}}
	_, fs := AIGValidate(v)
	if !aigHas(fs, AIGReasonAbsoluteName) {
		t.Fatalf("want absolute name, got %v", fs)
	}
}

func TestAIGSizeZero(t *testing.T) {
	h := aigHash()
	v := AIGIndexView{Entries: []AIGEntry{
		{Name: "a.ogg", Object: AIGObject{Hash: h, Size: 0}},
	}}
	_, fs := AIGValidate(v)
	if !aigHas(fs, AIGReasonSizeZeroOrBig) {
		t.Fatalf("want zero size, got %v", fs)
	}
}

func TestAIGDuplicateDiffHash(t *testing.T) {
	h1 := aigHash()
	h2 := "fedcba9876543210fedcba9876543210fedcba98"
	v := AIGIndexView{Entries: []AIGEntry{
		{Name: "a.ogg", Object: AIGObject{Hash: h1, Size: 10}},
		{Name: "a.ogg", Object: AIGObject{Hash: h2, Size: 12}},
	}}
	_, fs := AIGValidate(v)
	if !aigHas(fs, AIGReasonDuplicateName) {
		t.Fatalf("want duplicate name, got %v", fs)
	}
}

func TestAIGTotalMismatch(t *testing.T) {
	h := aigHash()
	v := AIGIndexView{DeclaredTotal: 999, Entries: []AIGEntry{
		{Name: "a.ogg", Object: AIGObject{Hash: h, Size: 10}},
	}}
	_, fs := AIGValidate(v)
	if !aigHas(fs, AIGReasonTotalSizeMismatch) {
		t.Fatalf("want total mismatch, got %v", fs)
	}
}

func TestAIGVirtualExecutable(t *testing.T) {
	h := aigHash()
	v := AIGIndexView{Virtual: true, Entries: []AIGEntry{
		{Name: "minecraft/evil.exe", Object: AIGObject{Hash: h, Size: 10}},
	}}
	_, fs := AIGValidate(v)
	if !aigHas(fs, AIGReasonExecutableVirtual) {
		t.Fatalf("want virtual executable, got %v", fs)
	}
}

func TestAIGVirtualMetaInf(t *testing.T) {
	h := aigHash()
	v := AIGIndexView{Virtual: true, Entries: []AIGEntry{
		{Name: "META-INF/x", Object: AIGObject{Hash: h, Size: 10}},
	}}
	_, fs := AIGValidate(v)
	if !aigHas(fs, AIGReasonExecutableVirtual) {
		t.Fatalf("want virtual meta-inf, got %v", fs)
	}
}

func TestAIGObjectPath(t *testing.T) {
	h := aigHash()
	got := AIGObjectPath(h)
	want := "objects/01/" + h
	if got != want {
		t.Fatalf("object path wrong %q", got)
	}
}
