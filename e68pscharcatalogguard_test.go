package main

import "testing"

func TestE68PSCClassifyBlock(t *testing.T) {
	for _, v := range E68PSCBlock { if E68PSCClassify(v) != E68PSCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68PSCClassifyWarn(t *testing.T) {
	for _, v := range E68PSCWarn { if E68PSCClassify(v) != E68PSCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68PSCClassifyAllow(t *testing.T) {
	for _, v := range E68PSCAllow { if E68PSCClassify(v) != E68PSCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68PSCClassifyUnknown(t *testing.T) {
	if E68PSCClassify("zzz-not-in-any-e68-catalog-77") != E68PSCClassUnknown { t.Fatal("unknown") }
}
