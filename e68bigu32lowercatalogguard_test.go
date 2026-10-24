package main

import "testing"

func TestE68BGLClassifyBlock(t *testing.T) {
	for _, v := range E68BGLBlock { if E68BGLClassify(v) != E68BGLClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68BGLClassifyWarn(t *testing.T) {
	for _, v := range E68BGLWarn { if E68BGLClassify(v) != E68BGLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68BGLClassifyAllow(t *testing.T) {
	for _, v := range E68BGLAllow { if E68BGLClassify(v) != E68BGLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68BGLClassifyUnknown(t *testing.T) {
	if E68BGLClassify("zzz-not-in-any-e68-catalog-77") != E68BGLClassUnknown { t.Fatal("unknown") }
}
