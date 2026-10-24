package main

import "testing"

func TestE68HXLClassifyBlock(t *testing.T) {
	for _, v := range E68HXLBlock { if E68HXLClassify(v) != E68HXLClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68HXLClassifyWarn(t *testing.T) {
	for _, v := range E68HXLWarn { if E68HXLClassify(v) != E68HXLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68HXLClassifyAllow(t *testing.T) {
	for _, v := range E68HXLAllow { if E68HXLClassify(v) != E68HXLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68HXLClassifyUnknown(t *testing.T) {
	if E68HXLClassify("zzz-not-in-any-e68-catalog-77") != E68HXLClassUnknown { t.Fatal("unknown") }
}
