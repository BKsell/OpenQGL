package main

import "testing"

func TestCDSimpleQuoted(t *testing.T) {
	r, err := ParseContentDisposition(`attachment; filename="mod.jar"`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Disposition != "attachment" || r.Filename != "mod.jar" {
		t.Fatalf("parse wrong: %+v", r)
	}
	if n := r.PreferredFilename(); n != "mod.jar" {
		t.Fatalf("preferred=%s", n)
	}
}

func TestCDTokenValue(t *testing.T) {
	r, err := ParseContentDisposition(`attachment; filename=mod-1.2.3.jar`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Filename != "mod-1.2.3.jar" {
		t.Fatalf("token filename=%s", r.Filename)
	}
}

func TestCDFilenameStarPreferred(t *testing.T) {
	r, err := ParseContentDisposition(`attachment; filename="fallback.bin"; filename*=UTF-8''real.jar`)
	if err != nil {
		t.Fatal(err)
	}
	if r.PreferredFilename() != "real.jar" {
		t.Fatalf("filename* must win, got %s", r.PreferredFilename())
	}
}

func TestCDFilenameStarPercentUTF8(t *testing.T) {
	// %E4%B8%AD = U+4E2D（中）
	name, err := ResolveDownloadFilename(`attachment; filename*=UTF-8''%E4%B8%AD.jar`)
	if err != nil {
		t.Fatal(err)
	}
	if name != "中.jar" {
		t.Fatalf("decoded=%q", name)
	}
}

func TestCDInlineDisposition(t *testing.T) {
	r, err := ParseContentDisposition(`inline; filename="p.png"`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Disposition != "inline" {
		t.Fatalf("disposition=%s", r.Disposition)
	}
}

func TestCDExtraParams(t *testing.T) {
	r, err := ParseContentDisposition(`attachment; filename="a"; size=123; creation-date="x"`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Params["size"] != "123" {
		t.Fatalf("params=%+v", r.Params)
	}
}

func TestCDRejectPathTraversal(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename="../../etc/passwd"`)
	if CDReason(err) != CDReasonPathSeparator {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectTraversalInStar(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename*=UTF-8''..%2F..%2Fx.jar`)
	if CDReason(err) != CDReasonPathSeparator {
		t.Fatalf("encoded slash must be caught after decode, reason=%s", CDReason(err))
	}
}

func TestCDRejectDrive(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename="C:evil.jar"`)
	if CDReason(err) != CDReasonDriveOrUNC {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectReservedDevice(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename="CON.jar"`)
	if CDReason(err) != CDReasonReservedDevice {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectLeadingDot(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename=".bashrc"`)
	if CDReason(err) != CDReasonLeadingDotSpace {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectDotsOnly(t *testing.T) {
	_, err := ResolveDownloadFilename(`attachment; filename="..."`)
	if CDReason(err) != CDReasonDotOrSpace {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectBadCharset(t *testing.T) {
	_, err := ParseContentDisposition(`attachment; filename*=ISO-8859-1''caf%E9.jar`)
	if CDReason(err) != CDReasonUnsafeCharset {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectBadPercent(t *testing.T) {
	_, err := ParseContentDisposition(`attachment; filename*=UTF-8''a%zz.jar`)
	if CDReason(err) != CDReasonBadPercent {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDRejectInvalidUTF8(t *testing.T) {
	// %FF 单独不是合法 UTF-8 起始字节。
	_, err := ParseContentDisposition(`attachment; filename*=UTF-8''a%FF.jar`)
	if CDReason(err) != CDReasonBadPercent {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDEmptyHeader(t *testing.T) {
	if _, err := ParseContentDisposition("   "); CDReason(err) != CDReasonEmpty {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDMalformedParam(t *testing.T) {
	// 缺少 '='
	if _, err := ParseContentDisposition(`attachment; filename`); CDReason(err) != CDReasonMalformed {
		t.Fatalf("missing = reason=%s", CDReason(err))
	}
	// 未闭合引号
	if _, err := ParseContentDisposition(`attachment; filename="abc`); CDReason(err) != CDReasonMalformed {
		t.Fatalf("unclosed quote reason=%s", CDReason(err))
	}
}

func TestCDNoFilename(t *testing.T) {
	if _, err := ResolveDownloadFilename(`attachment; size=10`); CDReason(err) != CDReasonNoFilename {
		t.Fatalf("reason=%s", CDReason(err))
	}
}

func TestCDQuotedPair(t *testing.T) {
	r, err := ParseContentDisposition(`attachment; filename="a\"b.jar"`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Filename != `a"b.jar` {
		t.Fatalf("quoted-pair decoded=%q", r.Filename)
	}
}

func TestCDTooLongHeader(t *testing.T) {
	big := "attachment; filename=" + string(make([]byte, 9000))
	_, err := ParseContentDisposition(big)
	if CDReason(err) != CDReasonMalformed {
		t.Fatalf("oversize header reason=%s", CDReason(err))
	}
}

func TestCDReasonHelper(t *testing.T) {
	if CDReason(nil) != "" {
		t.Fatal("nil error reason must be empty")
	}
	if DescribeCDReason(CDReasonControlChar) == "" {
		t.Fatal("description must not be empty")
	}
}

func TestCDResolveValidName(t *testing.T) {
	name, err := ResolveDownloadFilename(`attachment; filename="OptiFine_1.20.1.jar"`)
	if err != nil {
		t.Fatal(err)
	}
	if name != "OptiFine_1.20.1.jar" {
		t.Fatalf("name=%q", name)
	}
}
