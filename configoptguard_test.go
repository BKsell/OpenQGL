package main

import "testing"

func cfgHas(fs []CFGFinding, key, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason && f.Key == key {
			return true
		}
	}
	return false
}

func TestCFGIntGood(t *testing.T) {
	spec := CFGSpec{Key: "xmxMb", Kind: CFGKindInt, Min: 512, Max: 32768}
	safe, _ := CFGEvaluate(spec, CFGValue{IntVal: 4096}, CFGSourceLocal)
	if !safe {
		t.Fatal("in-range int should pass")
	}
}

func TestCFGIntNegative(t *testing.T) {
	spec := CFGSpec{Key: "threads", Kind: CFGKindInt, Min: 1, Max: 64}
	_, fs := CFGEvaluate(spec, CFGValue{IntVal: -2}, CFGSourceLocal)
	if !cfgHas(fs, "threads", CFGReasonNegativeOrZero) {
		t.Fatalf("want negative, got %v", fs)
	}
}

func TestCFGIntZero(t *testing.T) {
	spec := CFGSpec{Key: "threads", Kind: CFGKindInt, Min: 1, Max: 64}
	_, fs := CFGEvaluate(spec, CFGValue{IntVal: 0}, CFGSourceLocal)
	if !cfgHas(fs, "threads", CFGReasonNegativeOrZero) {
		t.Fatalf("want zero, got %v", fs)
	}
}

func TestCFGIntOutOfRange(t *testing.T) {
	spec := CFGSpec{Key: "xmxMb", Kind: CFGKindInt, Min: 512, Max: 32768}
	_, fs := CFGEvaluate(spec, CFGValue{IntVal: 999999}, CFGSourceLocal)
	if !cfgHas(fs, "xmxMb", CFGReasonOutOfRange) {
		t.Fatalf("want out of range, got %v", fs)
	}
}

func TestCFGBoolFalseString(t *testing.T) {
	spec := CFGSpec{Key: "fullscreen", Kind: CFGKindBool}
	// 弱解析陷阱：字符串 "false" 被当 true
	_, fs := CFGEvaluate(spec, CFGValue{BoolVal: true, RawBoolString: "false"}, CFGSourceLocal)
	if !cfgHas(fs, "fullscreen", CFGReasonBoolCoercion) {
		t.Fatalf("want false-parsed-true, got %v", fs)
	}
}

func TestCFGBoolValidStrings(t *testing.T) {
	spec := CFGSpec{Key: "fullscreen", Kind: CFGKindBool}
	for _, s := range []string{"true", "false", "1", "0", "yes", "no"} {
		v := CFGValue{RawBoolString: s}
		if s == "true" || s == "1" || s == "yes" {
			v.BoolVal = true
		}
		if safe, _ := CFGEvaluate(spec, v, CFGSourceLocal); !safe {
			t.Fatalf("canonical bool string %q should pass", s)
		}
	}
}

func TestCFGBoolJunkString(t *testing.T) {
	spec := CFGSpec{Key: "fullscreen", Kind: CFGKindBool}
	_, fs := CFGEvaluate(spec, CFGValue{RawBoolString: "maybe"}, CFGSourceLocal)
	if !cfgHas(fs, "fullscreen", CFGReasonBoolCoercion) {
		t.Fatalf("want junk bool, got %v", fs)
	}
}

func TestCFGDangerousRemote(t *testing.T) {
	spec := CFGSpec{Key: "skipHashCheck", Kind: CFGKindBool, Dangerous: true}
	_, fs := CFGEvaluate(spec, CFGValue{BoolVal: true}, CFGSourceRemote)
	if !cfgHas(fs, "skipHashCheck", CFGReasonDangerousToggle) {
		t.Fatalf("want dangerous remote, got %v", fs)
	}
}

func TestCFGDangerousLocalAllowed(t *testing.T) {
	spec := CFGSpec{Key: "skipHashCheck", Kind: CFGKindBool, Dangerous: true}
	safe, _ := CFGEvaluate(spec, CFGValue{BoolVal: true}, CFGSourceLocal)
	if !safe {
		t.Fatal("locally-set dangerous toggle is user responsibility and passes")
	}
}

func TestCFGStringTooLong(t *testing.T) {
	spec := CFGSpec{Key: "jvmArgs", Kind: CFGKindString, MaxLen: 64}
	long := ""
	for i := 0; i < 100; i++ {
		long += "x"
	}
	_, fs := CFGEvaluate(spec, CFGValue{StrVal: long}, CFGSourceLocal)
	if !cfgHas(fs, "jvmArgs", CFGReasonStringTooLong) {
		t.Fatalf("want too long, got %v", fs)
	}
}

func TestCFGStringNewline(t *testing.T) {
	spec := CFGSpec{Key: "jvmArgs", Kind: CFGKindString, MaxLen: 1024}
	_, fs := CFGEvaluate(spec, CFGValue{StrVal: "-Xmx2G\n-evil"}, CFGSourceRemote)
	if !cfgHas(fs, "jvmArgs", CFGReasonNewlineInValue) {
		t.Fatalf("want newline, got %v", fs)
	}
}

func TestCFGEnum(t *testing.T) {
	spec := CFGSpec{Key: "gc", Kind: CFGKindEnum,
		Allowed: map[string]bool{"G1GC": true, "ZGC": true, "ParallelGC": true}}
	if safe, _ := CFGEvaluate(spec, CFGValue{StrVal: "ZGC"}, CFGSourceLocal); !safe {
		t.Fatal("allowed enum should pass")
	}
	_, fs := CFGEvaluate(spec, CFGValue{StrVal: "EvilGC"}, CFGSourceLocal)
	if !cfgHas(fs, "gc", CFGReasonEnumInvalid) {
		t.Fatalf("want invalid enum, got %v", fs)
	}
}

func TestCFGMany(t *testing.T) {
	specs := []CFGSpec{
		{Key: "a", Kind: CFGKindInt, Min: 1, Max: 10},
		{Key: "b", Kind: CFGKindBool},
	}
	vals := []CFGValue{{IntVal: 5}, {BoolVal: true}}
	safe, _ := CFGEvaluateMany(specs, vals, []CFGSource{CFGSourceLocal, CFGSourceLocal})
	if !safe {
		t.Fatal("valid batch should pass")
	}
}
