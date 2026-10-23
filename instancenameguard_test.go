package main

import "testing"

func ingHas(fs []INGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestINGClean(t *testing.T) {
	pol := DefaultINGPolicy()
	comp, key, safe, _ := INGSanitize("Fabric 1.20.1", pol)
	if !safe || comp != "Fabric 1.20.1" || key != "fabric 1.20.1" {
		t.Fatalf("clean name wrong comp=%q key=%q safe=%v", comp, key, safe)
	}
}

func TestINGTraversal(t *testing.T) {
	pol := DefaultINGPolicy()
	comp, _, _, fs := INGSanitize("../../etc", pol)
	if !ingHas(fs, INGReasonTraversal) {
		t.Fatalf("want traversal, got %v", fs)
	}
	if comp == "" {
		t.Fatal("component should be replaced not empty")
	}
}

func TestINGIllegalChar(t *testing.T) {
	pol := DefaultINGPolicy()
	comp, _, _, fs := INGSanitize(`a:b*c?`, pol)
	if !ingHas(fs, INGReasonIllegalChar) {
		t.Fatalf("want illegal char, got %v", fs)
	}
	for _, c := range comp {
		if c == ':' || c == '*' || c == '?' {
			t.Fatalf("illegal char remained in %q", comp)
		}
	}
}

func TestINGReserved(t *testing.T) {
	pol := DefaultINGPolicy()
	comp, _, _, fs := INGSanitize("CON", pol)
	if !ingHas(fs, INGReasonReservedDevice) {
		t.Fatalf("want reserved, got %v", fs)
	}
	if comp == "CON" {
		t.Fatalf("reserved name must be prefixed, got %q", comp)
	}
}

func TestINGTrailingDot(t *testing.T) {
	pol := DefaultINGPolicy()
	comp, _, _, fs := INGSanitize("World.", pol)
	if !ingHas(fs, INGReasonTrailingSpaceDot) {
		t.Fatalf("want trailing dot, got %v", fs)
	}
	if comp != "World" {
		t.Fatalf("trailing dot not trimmed %q", comp)
	}
}

func TestINGEmpty(t *testing.T) {
	pol := DefaultINGPolicy()
	comp, _, safe, fs := INGSanitize("   ", pol)
	if safe || !ingHas(fs, INGReasonEmpty) {
		t.Fatalf("want empty, safe=%v fs=%v", safe, fs)
	}
	if comp == "" {
		t.Fatal("empty must become fallback")
	}
}

func TestINGTooLong(t *testing.T) {
	pol := DefaultINGPolicy()
	pol.MaxComponentLength = 10
	long := "abcdefghijklmnop"
	comp, _, _, fs := INGSanitize(long, pol)
	if !ingHas(fs, INGReasonTooLong) {
		t.Fatalf("want too long, got %v", fs)
	}
	if len(comp) > 10 {
		t.Fatalf("component not truncated: %d", len(comp))
	}
}

func TestINGControl(t *testing.T) {
	pol := DefaultINGPolicy()
	_, _, _, fs := INGSanitize("ab\x00cd", pol)
	if !ingHas(fs, INGReasonControlChar) {
		t.Fatalf("want control char, got %v", fs)
	}
}

func TestINGDotDot(t *testing.T) {
	pol := DefaultINGPolicy()
	comp, _, _, fs := INGSanitize("..", pol)
	if !ingHas(fs, INGReasonDotName) && !ingHas(fs, INGReasonTraversal) {
		t.Fatalf("want dot name/traversal, got %v", fs)
	}
	if comp == ".." {
		t.Fatal("dotdot must be neutralized")
	}
}

func TestINGCollision(t *testing.T) {
	existing := map[string]bool{"my world": true}
	if !INGCollides(existing, "MY WORLD") {
		t.Fatal("case-folded key should collide")
	}
	if INGCollides(existing, "other world") {
		t.Fatal("different name should not collide")
	}
}
