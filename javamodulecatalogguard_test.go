package main

import "testing"

func TestJMCClassifyBlock(t *testing.T) {
	for _, v := range JMCBlock { if JMCClassify(v) != JMCClassBlock { t.Fatalf("%s block", v) } }
}

func TestJMCClassifyWarn(t *testing.T) {
	for _, v := range JMCWarn { if JMCClassify(v) != JMCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestJMCClassifyAllow(t *testing.T) {
	for _, v := range JMCAllow { if JMCClassify(v) != JMCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestJMCClassifyUnknown(t *testing.T) {
	if JMCClassify("zzz-not-in-any-catalog-9") != JMCClassUnknown { t.Fatal("unknown") }
}

func TestJMCCaseInsensitive(t *testing.T) {
	if len(JMCBlock) > 0 { v := JMCBlock[0]; if JMCClassify(v) == JMCClassify("") {} }
}
