package main

import "testing"

func TestE68JUUClassifyBlock(t *testing.T) {
	for _, v := range E68JUUBlock { if E68JUUClassify(v) != E68JUUClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68JUUClassifyWarn(t *testing.T) {
	for _, v := range E68JUUWarn { if E68JUUClassify(v) != E68JUUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68JUUClassifyAllow(t *testing.T) {
	for _, v := range E68JUUAllow { if E68JUUClassify(v) != E68JUUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68JUUClassifyUnknown(t *testing.T) {
	if E68JUUClassify("zzz-not-in-any-e68-catalog-77") != E68JUUClassUnknown { t.Fatal("unknown") }
}
