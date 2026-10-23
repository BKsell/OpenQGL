package main

import "testing"

func TestWNNormalFile(t *testing.T) {
	if safe, _ := WNAuditPath(`C:\Users\me\world\level.dat`); !safe {
		t.Fatal("ordinary path should pass")
	}
}

func TestWNReservedCon(t *testing.T) {
	_, fs := WNAuditPath(`C:\download\CON.txt`)
	if !WNHasReason(fs, WNReasonReservedDevice) {
		t.Fatalf("CON.txt must be treated as reserved device: %v", fs)
	}
}

func TestWNReservedCom1(t *testing.T) {
	_, fs := WNAuditPath(`out\COM1`)
	if !WNHasReason(fs, WNReasonReservedDevice) {
		t.Fatalf("COM1 must be reserved: %v", fs)
	}
}

func TestWNReservedCaseInsensitive(t *testing.T) {
	_, fs := WNAuditPath(`nul.log`)
	if !WNHasReason(fs, WNReasonReservedDevice) {
		t.Fatalf("nul.log lowercase must be reserved: %v", fs)
	}
}

func TestWNAlternateStream(t *testing.T) {
	_, fs := WNAuditPath(`C:\temp\notes.txt:hidden`)
	if !WNHasReason(fs, WNReasonAlternateStream) {
		t.Fatalf("ADS colon segment must flag: %v", fs)
	}
}

func TestWNDriveLetterOK(t *testing.T) {
	if safe, _ := WNAuditPath(`D:\games\run.bat`); !safe {
		t.Fatal("drive letter D: must not be treated as ADS")
	}
}

func TestWNTrailingDot(t *testing.T) {
	_, fs := WNAuditPath(`C:\x\evil.`)
	if !WNHasReason(fs, WNReasonTrailingDotSpace) {
		t.Fatalf("trailing dot must flag normalization bypass: %v", fs)
	}
}

func TestWNTrailingSpace(t *testing.T) {
	_, fs := WNAuditPath(`C:\x\evil `)
	if !WNHasReason(fs, WNReasonTrailingDotSpace) {
		t.Fatalf("trailing space must flag: %v", fs)
	}
}

func TestWNExtendedPrefix(t *testing.T) {
	_, fs := WNAuditPath(`\\?\C:\very\long`)
	if !WNHasReason(fs, WNReasonExtendedPrefix) {
		t.Fatalf("win32 extended prefix must flag: %v", fs)
	}
}

func TestWNDevicePrefix(t *testing.T) {
	_, fs := WNAuditPath(`\\.\PhysicalDrive0`)
	if !WNHasReason(fs, WNReasonExtendedPrefix) {
		t.Fatalf("win32 device prefix must flag: %v", fs)
	}
}
