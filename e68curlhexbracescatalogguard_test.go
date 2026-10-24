package main

import "testing"

func TestE68CHBClassifyBlock(t *testing.T) {
	for _, v := range E68CHBBlock { if E68CHBClassify(v) != E68CHBClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68CHBClassifyWarn(t *testing.T) {
	for _, v := range E68CHBWarn { if E68CHBClassify(v) != E68CHBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68CHBClassifyAllow(t *testing.T) {
	for _, v := range E68CHBAllow { if E68CHBClassify(v) != E68CHBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68CHBClassifyUnknown(t *testing.T) {
	if E68CHBClassify("zzz-not-in-any-e68-catalog-77") != E68CHBClassUnknown { t.Fatal("unknown") }
}
