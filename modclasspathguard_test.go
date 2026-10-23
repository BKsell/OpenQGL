package main

import "testing"

func TestMCCleanLibrary(t *testing.T) {
	m := MCManifest{ClassPathEntries: []string{"lib/dep.jar", "other.jar"}}
	if safe, _ := MCAuditManifest(m); !safe {
		t.Fatal("relative in-dir classpath of a library should pass")
	}
}

func TestMCClassPathTraversal(t *testing.T) {
	m := MCManifest{ClassPathEntries: []string{`..\..\..\Windows\evil.jar`}}
	_, fs := MCAuditManifest(m)
	if !MCHasReason(fs, MCReasonClassPathTraversal) {
		t.Fatalf(".. traversal in classpath must flag: %v", fs)
	}
}

func TestMCClassPathAbsolute(t *testing.T) {
	m := MCManifest{ClassPathEntries: []string{`C:\Windows\evil.jar`}}
	_, fs := MCAuditManifest(m)
	if !MCHasReason(fs, MCReasonClassPathAbsolute) {
		t.Fatalf("absolute classpath must flag: %v", fs)
	}
}

func TestMCClassPathUNC(t *testing.T) {
	m := MCManifest{ClassPathEntries: []string{`\\server\share\evil.jar`}}
	_, fs := MCAuditManifest(m)
	if !MCHasReason(fs, MCReasonClassPathAbsolute) {
		t.Fatalf("UNC classpath must flag: %v", fs)
	}
}

func TestMCClassPathScheme(t *testing.T) {
	m := MCManifest{ClassPathEntries: []string{"http://evil/x.jar"}}
	_, fs := MCAuditManifest(m)
	if !MCHasReason(fs, MCReasonClassPathScheme) {
		t.Fatalf("url scheme classpath must flag: %v", fs)
	}
}

func TestMCAgentClass(t *testing.T) {
	m := MCManifest{PremainClass: "evil.Agent"}
	_, fs := MCAuditManifest(m)
	if !MCHasReason(fs, MCReasonAgentClass) {
		t.Fatalf("Premain-Class javaagent must flag: %v", fs)
	}
}

func TestMCLauncherAgent(t *testing.T) {
	m := MCManifest{LauncherAgentClass: "evil.Launch"}
	_, fs := MCAuditManifest(m)
	if !MCHasReason(fs, MCReasonAgentClass) {
		t.Fatalf("Launcher-Agent-Class must flag: %v", fs)
	}
}

func TestMCMainClassOnLibrary(t *testing.T) {
	m := MCManifest{MainClass: "evil.Main", IsExecutableJar: false}
	_, fs := MCAuditManifest(m)
	if !MCHasReason(fs, MCReasonUnexpectedMain) {
		t.Fatalf("Main-Class on a library jar must flag: %v", fs)
	}
}

func TestMCMainClassOnExecutableOK(t *testing.T) {
	m := MCManifest{MainClass: "net.game.Launch", IsExecutableJar: true}
	if safe, _ := MCAuditManifest(m); !safe {
		t.Fatal("Main-Class is expected on an executable jar")
	}
}

func TestMCEntryCRLF(t *testing.T) {
	m := MCManifest{ClassPathEntries: []string{"a.jar\r\nEvil: x"}}
	_, fs := MCAuditManifest(m)
	if !MCHasReason(fs, MCReasonEntryCRLF) {
		t.Fatalf("CRLF in manifest value must flag: %v", fs)
	}
}
