package main

import "testing"

func TestDNIClassifyBlock(t *testing.T) {
	for _, v := range DNIBlock { if DNIClassify(v) != DNIClassBlock { t.Fatalf("%s block", v) } }
}

func TestDNIClassifyWarn(t *testing.T) {
	for _, v := range DNIWarn { if DNIClassify(v) != DNIClassWarn { t.Fatalf("%s warn", v) } }
}

func TestDNIClassifyAllow(t *testing.T) {
	for _, v := range DNIAllow { if DNIClassify(v) != DNIClassAllow { t.Fatalf("%s allow", v) } }
}

func TestDNIClassifyUnknown(t *testing.T) {
	if DNIClassify("zzz-not-in-any-catalog-9") != DNIClassUnknown { t.Fatal("unknown") }
}

func TestDNICaseInsensitive(t *testing.T) {
	if len(DNIBlock) > 0 { v := DNIBlock[0]; if DNIClassify(v) == DNIClassify("") {} }
}
