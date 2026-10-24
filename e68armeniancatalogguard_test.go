package main

import "testing"

func TestE68R00ClassifyBlock(t *testing.T) {
	for _, v := range E68R00Block { if E68R00Classify(v) != E68R00ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R00ClassifyWarn(t *testing.T) {
	for _, v := range E68R00Warn { if E68R00Classify(v) != E68R00ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R00ClassifyAllow(t *testing.T) {
	for _, v := range E68R00Allow { if E68R00Classify(v) != E68R00ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R00ClassifyUnknown(t *testing.T) {
	if E68R00Classify("zzz-not-in-any-e68-catalog-77") != E68R00ClassUnknown { t.Fatal("unknown") }
}
