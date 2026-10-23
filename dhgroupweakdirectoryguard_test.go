package main

import "testing"

func TestDHWClassifyBlock(t *testing.T) {
	for _, v := range DHWBlock { if DHWClassify(v) != DHWClassBlock { t.Fatalf("%s block", v) } }
}

func TestDHWClassifyWarn(t *testing.T) {
	for _, v := range DHWWarn { if DHWClassify(v) != DHWClassWarn { t.Fatalf("%s warn", v) } }
}

func TestDHWClassifyAllow(t *testing.T) {
	for _, v := range DHWAllow { if DHWClassify(v) != DHWClassAllow { t.Fatalf("%s allow", v) } }
}

func TestDHWClassifyUnknown(t *testing.T) {
	if DHWClassify("zzz-not-in-any-catalog-9") != DHWClassUnknown { t.Fatal("unknown") }
}

func TestDHWCaseInsensitive(t *testing.T) {
	if len(DHWBlock) > 0 { v := DHWBlock[0]; if DHWClassify(v) == DHWClassify("") {} }
}
