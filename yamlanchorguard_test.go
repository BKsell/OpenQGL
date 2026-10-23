package main

import "testing"

func ymlHasReason(fs []YMLFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestYMLClean(t *testing.T) {
	doc := []byte("name: sodium\nversion: 0.5.0\nlibs:\n  - name: fabric\n")
	if f := YMLScan(doc, DefaultYMLPolicy()); len(f) != 0 {
		t.Fatalf("clean yaml must pass: %v", f)
	}
}

func TestYMLUnsafePythonTag(t *testing.T) {
	pol := DefaultYMLPolicy()
	doc := []byte("!!python/object/apply:os.system ['echo hi']\n")
	if f := YMLScan(doc, pol); !ymlHasReason(f, YMLReasonUnsafeTag) {
		t.Fatal("python/object/apply must be flagged")
	}
}

func TestYMLUnsafeRubyTag(t *testing.T) {
	pol := DefaultYMLPolicy()
	doc := []byte("x: !!ruby/object:Gem::Installer\n")
	if f := YMLScan(doc, pol); !ymlHasReason(f, YMLReasonUnsafeTag) {
		t.Fatal("ruby object tag must be flagged")
	}
}

func TestYMLBillionLaughsFanout(t *testing.T) {
	pol := DefaultYMLPolicy()
	doc := []byte("a: &x v\n")
	refs := "b:\n"
	for i := 0; i < 70; i++ {
		refs += "  - *x\n"
	}
	doc = append(doc, []byte(refs)...)
	f := YMLScan(doc, pol)
	if !ymlHasReason(f, YMLReasonAliasFanout) {
		t.Fatalf("alias fanout must be flagged: %v", f)
	}
}

func TestYMLTooManyAnchors(t *testing.T) {
	pol := DefaultYMLPolicy()
	doc := []byte{}
	for i := 0; i < 70; i++ {
		doc = append(doc, []byte("k: &a")...)
		doc = append(doc, []byte(ymlItoa(i)+" v\n")...)
	}
	if f := YMLScan(doc, pol); !ymlHasReason(f, YMLReasonTooManyAnchors) {
		t.Fatal("too many anchors must be flagged")
	}
}

func TestYMLDocumentTooLarge(t *testing.T) {
	pol := DefaultYMLPolicy()
	pol.MaxDocumentBytes = 10
	big := make([]byte, 64)
	for i := range big {
		big[i] = 'a'
	}
	if f := YMLScan(big, pol); !ymlHasReason(f, YMLReasonDocumentTooLarge) {
		t.Fatal("oversized document must be flagged")
	}
}

func TestYMLQuotedSafe(t *testing.T) {
	// 引号里出现的危险标签文本不应误判。
	pol := DefaultYMLPolicy()
	doc := []byte("note: \"!!python/object/apply is dangerous\"\n")
	if f := YMLScan(doc, pol); ymlHasReason(f, YMLReasonUnsafeTag) {
		t.Fatalf("tag text inside quotes must not be flagged: %v", f)
	}
}

func TestYMLUnterminatedQuote(t *testing.T) {
	pol := DefaultYMLPolicy()
	doc := []byte("note: \"unterminated\n")
	if f := YMLScan(doc, pol); !ymlHasReason(f, YMLReasonQuotedUnterminated) {
		t.Fatal("unterminated quoted string must be flagged")
	}
}

func TestYMLIsSafe(t *testing.T) {
	if !YMLIsSafe([]byte("key: value\nlist:\n  - 1\n  - 2\n")) {
		t.Fatal("normal yaml must be safe")
	}
	if YMLIsSafe([]byte("!!python/object/apply:os.system []")) {
		t.Fatal("unsafe tag must not be safe")
	}
}
