package main

import "testing"

func TestE68PVWClassifyBlock(t *testing.T) {
	for _, v := range E68PVWBlock { if E68PVWClassify(v) != E68PVWClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68PVWClassifyWarn(t *testing.T) {
	for _, v := range E68PVWWarn { if E68PVWClassify(v) != E68PVWClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68PVWClassifyAllow(t *testing.T) {
	for _, v := range E68PVWAllow { if E68PVWClassify(v) != E68PVWClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68PVWClassifyUnknown(t *testing.T) {
	if E68PVWClassify("zzz-not-in-any-e68-catalog-77") != E68PVWClassUnknown { t.Fatal("unknown") }
}
