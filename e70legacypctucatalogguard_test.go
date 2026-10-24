package main

import "testing"

func TestE70LPUClassifyBlock(t *testing.T) {
	for _, v := range E70LPUBlock { if E70LPUClassify(v) != E70LPUClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70LPUClassifyWarn(t *testing.T) {
	for _, v := range E70LPUWarn { if E70LPUClassify(v) != E70LPUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70LPUClassifyAllow(t *testing.T) {
	for _, v := range E70LPUAllow { if E70LPUClassify(v) != E70LPUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70LPUClassifyUnknown(t *testing.T) {
	if E70LPUClassify("zzz-not-in-any-e70-catalog-99") != E70LPUClassUnknown { t.Fatal("unknown") }
}
