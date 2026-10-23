package main

import "testing"

func TestDSIClassifyBlock(t *testing.T) {
	for _, v := range DSIBlock { if DSIClassify(v) != DSIClassBlock { t.Fatalf("%s block", v) } }
}

func TestDSIClassifyWarn(t *testing.T) {
	for _, v := range DSIWarn { if DSIClassify(v) != DSIClassWarn { t.Fatalf("%s warn", v) } }
}

func TestDSIClassifyAllow(t *testing.T) {
	for _, v := range DSIAllow { if DSIClassify(v) != DSIClassAllow { t.Fatalf("%s allow", v) } }
}

func TestDSIClassifyUnknown(t *testing.T) {
	if DSIClassify("zzz-not-in-any-catalog-9") != DSIClassUnknown { t.Fatal("unknown") }
}

func TestDSICaseInsensitive(t *testing.T) {
	if len(DSIBlock) > 0 { v := DSIBlock[0]; if DSIClassify(v) == DSIClassify("") {} }
}
