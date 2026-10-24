package main

import "testing"

func TestE68H02ClassifyBlock(t *testing.T) {
	for _, v := range E68H02Block { if E68H02Classify(v) != E68H02ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68H02ClassifyWarn(t *testing.T) {
	for _, v := range E68H02Warn { if E68H02Classify(v) != E68H02ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68H02ClassifyAllow(t *testing.T) {
	for _, v := range E68H02Allow { if E68H02Classify(v) != E68H02ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68H02ClassifyUnknown(t *testing.T) {
	if E68H02Classify("zzz-not-in-any-e68-catalog-77") != E68H02ClassUnknown { t.Fatal("unknown") }
}
