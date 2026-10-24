package main

import "testing"

func TestE68PCDClassifyBlock(t *testing.T) {
	for _, v := range E68PCDBlock { if E68PCDClassify(v) != E68PCDClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68PCDClassifyWarn(t *testing.T) {
	for _, v := range E68PCDWarn { if E68PCDClassify(v) != E68PCDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68PCDClassifyAllow(t *testing.T) {
	for _, v := range E68PCDAllow { if E68PCDClassify(v) != E68PCDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68PCDClassifyUnknown(t *testing.T) {
	if E68PCDClassify("zzz-not-in-any-e68-catalog-77") != E68PCDClassUnknown { t.Fatal("unknown") }
}
