package main

import "testing"

func TestE68SQCClassifyBlock(t *testing.T) {
	for _, v := range E68SQCBlock { if E68SQCClassify(v) != E68SQCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68SQCClassifyWarn(t *testing.T) {
	for _, v := range E68SQCWarn { if E68SQCClassify(v) != E68SQCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68SQCClassifyAllow(t *testing.T) {
	for _, v := range E68SQCAllow { if E68SQCClassify(v) != E68SQCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68SQCClassifyUnknown(t *testing.T) {
	if E68SQCClassify("zzz-not-in-any-e68-catalog-77") != E68SQCClassUnknown { t.Fatal("unknown") }
}
