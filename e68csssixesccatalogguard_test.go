package main

import "testing"

func TestE68CSSClassifyBlock(t *testing.T) {
	for _, v := range E68CSSBlock { if E68CSSClassify(v) != E68CSSClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68CSSClassifyWarn(t *testing.T) {
	for _, v := range E68CSSWarn { if E68CSSClassify(v) != E68CSSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68CSSClassifyAllow(t *testing.T) {
	for _, v := range E68CSSAllow { if E68CSSClassify(v) != E68CSSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68CSSClassifyUnknown(t *testing.T) {
	if E68CSSClassify("zzz-not-in-any-e68-catalog-77") != E68CSSClassUnknown { t.Fatal("unknown") }
}
