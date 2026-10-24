package main

import "testing"

func TestE68JPLClassifyBlock(t *testing.T) {
	for _, v := range E68JPLBlock { if E68JPLClassify(v) != E68JPLClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68JPLClassifyWarn(t *testing.T) {
	for _, v := range E68JPLWarn { if E68JPLClassify(v) != E68JPLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68JPLClassifyAllow(t *testing.T) {
	for _, v := range E68JPLAllow { if E68JPLClassify(v) != E68JPLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68JPLClassifyUnknown(t *testing.T) {
	if E68JPLClassify("zzz-not-in-any-e68-catalog-77") != E68JPLClassUnknown { t.Fatal("unknown") }
}
