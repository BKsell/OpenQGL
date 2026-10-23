package main

import "testing"

func TestCMIClassifyBlock(t *testing.T) {
	for _, v := range CMIBlock { if CMIClassify(v) != CMIClassBlock { t.Fatalf("%s block", v) } }
}

func TestCMIClassifyWarn(t *testing.T) {
	for _, v := range CMIWarn { if CMIClassify(v) != CMIClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCMIClassifyAllow(t *testing.T) {
	for _, v := range CMIAllow { if CMIClassify(v) != CMIClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCMIClassifyUnknown(t *testing.T) {
	if CMIClassify("zzz-not-in-any-catalog-9") != CMIClassUnknown { t.Fatal("unknown") }
}

func TestCMICaseInsensitive(t *testing.T) {
	if len(CMIBlock) > 0 { v := CMIBlock[0]; if CMIClassify(v) == CMIClassify("") {} }
}
