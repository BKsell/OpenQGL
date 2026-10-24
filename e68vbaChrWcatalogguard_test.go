package main

import "testing"

func TestE68VBWClassifyBlock(t *testing.T) {
	for _, v := range E68VBWBlock { if E68VBWClassify(v) != E68VBWClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68VBWClassifyWarn(t *testing.T) {
	for _, v := range E68VBWWarn { if E68VBWClassify(v) != E68VBWClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68VBWClassifyAllow(t *testing.T) {
	for _, v := range E68VBWAllow { if E68VBWClassify(v) != E68VBWClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68VBWClassifyUnknown(t *testing.T) {
	if E68VBWClassify("zzz-not-in-any-e68-catalog-77") != E68VBWClassUnknown { t.Fatal("unknown") }
}
