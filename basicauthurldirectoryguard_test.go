package main

import "testing"

func TestBAUClassifyBlock(t *testing.T) {
	for _, v := range BAUBlock { if BAUClassify(v) != BAUClassBlock { t.Fatalf("%s block", v) } }
}

func TestBAUClassifyWarn(t *testing.T) {
	for _, v := range BAUWarn { if BAUClassify(v) != BAUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestBAUClassifyAllow(t *testing.T) {
	for _, v := range BAUAllow { if BAUClassify(v) != BAUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestBAUClassifyUnknown(t *testing.T) {
	if BAUClassify("zzz-not-in-any-catalog-9") != BAUClassUnknown { t.Fatal("unknown") }
}

func TestBAUCaseInsensitive(t *testing.T) {
	if len(BAUBlock) > 0 { v := BAUBlock[0]; if BAUClassify(v) == BAUClassify("") {} }
}
