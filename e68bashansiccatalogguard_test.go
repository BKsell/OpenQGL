package main

import "testing"

func TestE68BSHClassifyBlock(t *testing.T) {
	for _, v := range E68BSHBlock { if E68BSHClassify(v) != E68BSHClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68BSHClassifyWarn(t *testing.T) {
	for _, v := range E68BSHWarn { if E68BSHClassify(v) != E68BSHClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68BSHClassifyAllow(t *testing.T) {
	for _, v := range E68BSHAllow { if E68BSHClassify(v) != E68BSHClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68BSHClassifyUnknown(t *testing.T) {
	if E68BSHClassify("zzz-not-in-any-e68-catalog-77") != E68BSHClassUnknown { t.Fatal("unknown") }
}
