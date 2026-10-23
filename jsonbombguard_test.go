package main

import "testing"

func jbgHas(fs []JBGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestJBGClean(t *testing.T) {
	pol := DefaultJBGPolicy()
	safe, fs := JBGValidate([]byte(`{"a":1,"b":[true,false,null],"c":"x"}`), pol)
	if !safe {
		t.Fatalf("clean json unsafe: %v", fs)
	}
}

func TestJBGDepthBomb(t *testing.T) {
	pol := DefaultJBGPolicy()
	pol.MaxDepth = 5
	var b []byte
	for i := 0; i < 10; i++ {
		b = append(b, '[')
	}
	for i := 0; i < 10; i++ {
		b = append(b, ']')
	}
	_, fs := JBGValidate(b, pol)
	if !jbgHas(fs, JBGReasonTooDeep) {
		t.Fatalf("want too deep, got %v", fs)
	}
}

func TestJBGDuplicateKey(t *testing.T) {
	pol := DefaultJBGPolicy()
	_, fs := JBGValidate([]byte(`{"a":1,"a":2}`), pol)
	if !jbgHas(fs, JBGReasonDuplicateKey) {
		t.Fatalf("want dup key, got %v", fs)
	}
}

func TestJBGDuplicateKeyAllowed(t *testing.T) {
	pol := DefaultJBGPolicy()
	pol.RejectDupKeys = false
	safe, _ := JBGValidate([]byte(`{"a":1,"a":2}`), pol)
	if !safe {
		t.Fatal("dup keys tolerated under policy")
	}
}

func TestJBGLongString(t *testing.T) {
	pol := DefaultJBGPolicy()
	pol.MaxStringLength = 4
	_, fs := JBGValidate([]byte(`"abcdef"`), pol)
	if !jbgHas(fs, JBGReasonStringTooLong) {
		t.Fatalf("want long string, got %v", fs)
	}
}

func TestJBGLongNumber(t *testing.T) {
	pol := DefaultJBGPolicy()
	pol.MaxNumberLength = 5
	_, fs := JBGValidate([]byte(`12345678901234567890`), pol)
	if !jbgHas(fs, JBGReasonNumberTooLong) {
		t.Fatalf("want long number, got %v", fs)
	}
}

func TestJGBadExponent(t *testing.T) {
	pol := DefaultJBGPolicy()
	_, fs := JBGValidate([]byte(`1e`), pol)
	if !jbgHas(fs, JBGReasonNumberBadExp) {
		t.Fatalf("want bad exponent, got %v", fs)
	}
}

func TestJBGTruncatedObject(t *testing.T) {
	pol := DefaultJBGPolicy()
	_, fs := JBGValidate([]byte(`{"a":1`), pol)
	if !jbgHas(fs, JBGReasonTruncated) {
		t.Fatalf("want truncated, got %v", fs)
	}
}

func TestJBGEmpty(t *testing.T) {
	pol := DefaultJBGPolicy()
	safe, fs := JBGValidate(nil, pol)
	if safe || !jbgHas(fs, JBGReasonEmpty) {
		t.Fatalf("want empty, got %v", fs)
	}
}

func TestJBGNestedObjectNoFalseDup(t *testing.T) {
	pol := DefaultJBGPolicy()
	// 内外层同名键不算重复
	safe, fs := JBGValidate([]byte(`{"a":{"a":1}}`), pol)
	if !safe {
		t.Fatalf("nested same-name key should be fine: %v", fs)
	}
}

func TestJBGEscapedString(t *testing.T) {
	pol := DefaultJBGPolicy()
	safe, _ := JBGValidate([]byte(`{"a":"he says \"hi\" \n ok"}`), pol)
	if !safe {
		t.Fatal("escaped string should parse")
	}
}

func TestJBGTooManyTokens(t *testing.T) {
	pol := DefaultJBGPolicy()
	pol.MaxTokens = 3
	_, fs := JBGValidate([]byte(`[1,2,3,4,5]`), pol)
	if !jbgHas(fs, JBGReasonTooManyTokens) {
		t.Fatalf("want too many tokens, got %v", fs)
	}
}
