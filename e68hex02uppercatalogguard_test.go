package main

import "testing"

func TestE68H03ClassifyBlock(t *testing.T) {
	for _, v := range E68H03Block { if E68H03Classify(v) != E68H03ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68H03ClassifyWarn(t *testing.T) {
	for _, v := range E68H03Warn { if E68H03Classify(v) != E68H03ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68H03ClassifyAllow(t *testing.T) {
	for _, v := range E68H03Allow { if E68H03Classify(v) != E68H03ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68H03ClassifyUnknown(t *testing.T) {
	if E68H03Classify("zzz-not-in-any-e68-catalog-77") != E68H03ClassUnknown { t.Fatal("unknown") }
}
