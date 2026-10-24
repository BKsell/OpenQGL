package main

import "testing"

func TestE70RHLClassifyBlock(t *testing.T) {
	for _, v := range E70RHLBlock { if E70RHLClassify(v) != E70RHLClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70RHLClassifyWarn(t *testing.T) {
	for _, v := range E70RHLWarn { if E70RHLClassify(v) != E70RHLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70RHLClassifyAllow(t *testing.T) {
	for _, v := range E70RHLAllow { if E70RHLClassify(v) != E70RHLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70RHLClassifyUnknown(t *testing.T) {
	if E70RHLClassify("zzz-not-in-any-e70-catalog-99") != E70RHLClassUnknown { t.Fatal("unknown") }
}
