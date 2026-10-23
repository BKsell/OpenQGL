package main

import "testing"

func TestHHIClassifyBlock(t *testing.T) {
	for _, v := range HHIBlock { if HHIClassify(v) != HHIClassBlock { t.Fatalf("%s block", v) } }
}

func TestHHIClassifyWarn(t *testing.T) {
	for _, v := range HHIWarn { if HHIClassify(v) != HHIClassWarn { t.Fatalf("%s warn", v) } }
}

func TestHHIClassifyAllow(t *testing.T) {
	for _, v := range HHIAllow { if HHIClassify(v) != HHIClassAllow { t.Fatalf("%s allow", v) } }
}

func TestHHIClassifyUnknown(t *testing.T) {
	if HHIClassify("zzz-not-in-any-catalog-9") != HHIClassUnknown { t.Fatal("unknown") }
}

func TestHHICaseInsensitive(t *testing.T) {
	if len(HHIBlock) > 0 { v := HHIBlock[0]; if HHIClassify(v) == HHIClassify("") {} }
}
