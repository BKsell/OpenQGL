package main

import "testing"

func TestE68BGUClassifyBlock(t *testing.T) {
	for _, v := range E68BGUBlock { if E68BGUClassify(v) != E68BGUClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68BGUClassifyWarn(t *testing.T) {
	for _, v := range E68BGUWarn { if E68BGUClassify(v) != E68BGUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68BGUClassifyAllow(t *testing.T) {
	for _, v := range E68BGUAllow { if E68BGUClassify(v) != E68BGUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68BGUClassifyUnknown(t *testing.T) {
	if E68BGUClassify("zzz-not-in-any-e68-catalog-77") != E68BGUClassUnknown { t.Fatal("unknown") }
}
