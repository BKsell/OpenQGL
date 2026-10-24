package main

import "testing"

func TestE68CUUClassifyBlock(t *testing.T) {
	for _, v := range E68CUUBlock { if E68CUUClassify(v) != E68CUUClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68CUUClassifyWarn(t *testing.T) {
	for _, v := range E68CUUWarn { if E68CUUClassify(v) != E68CUUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68CUUClassifyAllow(t *testing.T) {
	for _, v := range E68CUUAllow { if E68CUUClassify(v) != E68CUUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68CUUClassifyUnknown(t *testing.T) {
	if E68CUUClassify("zzz-not-in-any-e68-catalog-77") != E68CUUClassUnknown { t.Fatal("unknown") }
}
