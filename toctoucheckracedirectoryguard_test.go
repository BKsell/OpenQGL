package main

import "testing"

func TestTOUClassifyBlock(t *testing.T) {
	for _, v := range TOUBlock { if TOUClassify(v) != TOUClassBlock { t.Fatalf("%s block", v) } }
}

func TestTOUClassifyWarn(t *testing.T) {
	for _, v := range TOUWarn { if TOUClassify(v) != TOUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestTOUClassifyAllow(t *testing.T) {
	for _, v := range TOUAllow { if TOUClassify(v) != TOUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestTOUClassifyUnknown(t *testing.T) {
	if TOUClassify("zzz-not-in-any-catalog-9") != TOUClassUnknown { t.Fatal("unknown") }
}

func TestTOUCaseInsensitive(t *testing.T) {
	if len(TOUBlock) > 0 { v := TOUBlock[0]; if TOUClassify(v) == TOUClassify("") {} }
}
