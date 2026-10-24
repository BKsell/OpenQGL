package main

import "testing"

func TestE68HXUClassifyBlock(t *testing.T) {
	for _, v := range E68HXUBlock { if E68HXUClassify(v) != E68HXUClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68HXUClassifyWarn(t *testing.T) {
	for _, v := range E68HXUWarn { if E68HXUClassify(v) != E68HXUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68HXUClassifyAllow(t *testing.T) {
	for _, v := range E68HXUAllow { if E68HXUClassify(v) != E68HXUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68HXUClassifyUnknown(t *testing.T) {
	if E68HXUClassify("zzz-not-in-any-e68-catalog-77") != E68HXUClassUnknown { t.Fatal("unknown") }
}
