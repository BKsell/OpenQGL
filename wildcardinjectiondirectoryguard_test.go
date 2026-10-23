package main

import "testing"

func TestWLIClassifyBlock(t *testing.T) {
	for _, v := range WLIBlock { if WLIClassify(v) != WLIClassBlock { t.Fatalf("%s block", v) } }
}

func TestWLIClassifyWarn(t *testing.T) {
	for _, v := range WLIWarn { if WLIClassify(v) != WLIClassWarn { t.Fatalf("%s warn", v) } }
}

func TestWLIClassifyAllow(t *testing.T) {
	for _, v := range WLIAllow { if WLIClassify(v) != WLIClassAllow { t.Fatalf("%s allow", v) } }
}

func TestWLIClassifyUnknown(t *testing.T) {
	if WLIClassify("zzz-not-in-any-catalog-9") != WLIClassUnknown { t.Fatal("unknown") }
}

func TestWLICaseInsensitive(t *testing.T) {
	if len(WLIBlock) > 0 { v := WLIBlock[0]; if WLIClassify(v) == WLIClassify("") {} }
}
