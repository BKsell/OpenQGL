package main

import "testing"

func TestE68PLBClassifyBlock(t *testing.T) {
	for _, v := range E68PLBBlock { if E68PLBClassify(v) != E68PLBClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68PLBClassifyWarn(t *testing.T) {
	for _, v := range E68PLBWarn { if E68PLBClassify(v) != E68PLBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68PLBClassifyAllow(t *testing.T) {
	for _, v := range E68PLBAllow { if E68PLBClassify(v) != E68PLBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68PLBClassifyUnknown(t *testing.T) {
	if E68PLBClassify("zzz-not-in-any-e68-catalog-77") != E68PLBClassUnknown { t.Fatal("unknown") }
}
