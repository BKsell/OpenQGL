package main

import "testing"

func TestE68H3PClassifyBlock(t *testing.T) {
	for _, v := range E68H3PBlock { if E68H3PClassify(v) != E68H3PClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68H3PClassifyWarn(t *testing.T) {
	for _, v := range E68H3PWarn { if E68H3PClassify(v) != E68H3PClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68H3PClassifyAllow(t *testing.T) {
	for _, v := range E68H3PAllow { if E68H3PClassify(v) != E68H3PClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68H3PClassifyUnknown(t *testing.T) {
	if E68H3PClassify("zzz-not-in-any-e68-catalog-77") != E68H3PClassUnknown { t.Fatal("unknown") }
}
