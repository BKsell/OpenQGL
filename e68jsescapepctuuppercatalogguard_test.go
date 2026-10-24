package main

import "testing"

func TestE68JPUClassifyBlock(t *testing.T) {
	for _, v := range E68JPUBlock { if E68JPUClassify(v) != E68JPUClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68JPUClassifyWarn(t *testing.T) {
	for _, v := range E68JPUWarn { if E68JPUClassify(v) != E68JPUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68JPUClassifyAllow(t *testing.T) {
	for _, v := range E68JPUAllow { if E68JPUClassify(v) != E68JPUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68JPUClassifyUnknown(t *testing.T) {
	if E68JPUClassify("zzz-not-in-any-e68-catalog-77") != E68JPUClassUnknown { t.Fatal("unknown") }
}
