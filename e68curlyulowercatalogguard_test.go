package main

import "testing"

func TestE68CULClassifyBlock(t *testing.T) {
	for _, v := range E68CULBlock { if E68CULClassify(v) != E68CULClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68CULClassifyWarn(t *testing.T) {
	for _, v := range E68CULWarn { if E68CULClassify(v) != E68CULClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68CULClassifyAllow(t *testing.T) {
	for _, v := range E68CULAllow { if E68CULClassify(v) != E68CULClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68CULClassifyUnknown(t *testing.T) {
	if E68CULClassify("zzz-not-in-any-e68-catalog-77") != E68CULClassUnknown { t.Fatal("unknown") }
}
