package main

import "testing"

func TestE68CSEClassifyBlock(t *testing.T) {
	for _, v := range E68CSEBlock { if E68CSEClassify(v) != E68CSEClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68CSEClassifyWarn(t *testing.T) {
	for _, v := range E68CSEWarn { if E68CSEClassify(v) != E68CSEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68CSEClassifyAllow(t *testing.T) {
	for _, v := range E68CSEAllow { if E68CSEClassify(v) != E68CSEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68CSEClassifyUnknown(t *testing.T) {
	if E68CSEClassify("zzz-not-in-any-e68-catalog-77") != E68CSEClassUnknown { t.Fatal("unknown") }
}
