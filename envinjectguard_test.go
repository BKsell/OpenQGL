package main

import "testing"

func TestSplitOptionTokens(t *testing.T) {
	toks := splitOptionTokens(`-Xmx2G -javaagent:"C:\Program Files\a.jar" --add-opens=java.base/java.lang=ALL-UNNAMED`)
	want := []string{
		"-Xmx2G",
		`-javaagent:C:\Program Files\a.jar`,
		"--add-opens=java.base/java.lang=ALL-UNNAMED",
	}
	if len(toks) != len(want) {
		t.Fatalf("got %v want %v", toks, want)
	}
	for i := range want {
		if toks[i] != want[i] {
			t.Fatalf("token %d = %q want %q", i, toks[i], want[i])
		}
	}
}

func TestAuditOptionVariableBlocksAgents(t *testing.T) {
	lim := defaultEnvInjectionLimits()
	for _, val := range []string{
		"-javaagent:evil.jar",
		`-agentpath:C:\x.dll`,
		"-Xverify:none",
		"-noverify",
		"-Djavax.net.ssl.trustStore=evil.jks",
		"-Dcom.sun.management.jmxremote.port=9000",
		"-Dlog4j.configurationFile=file:///x.xml",
	} {
		hits := auditOptionVariable("JAVA_TOOL_OPTIONS", val, lim)
		found := false
		for _, h := range hits {
			if h.Reason == "dangerous-option" {
				found = true
			}
		}
		if !found {
			t.Fatalf("val %q expected dangerous-option, got %+v", val, hits)
		}
	}
}

func TestAuditOptionVariableDeepOpen(t *testing.T) {
	lim := defaultEnvInjectionLimits()
	hits := auditOptionVariable("JDK_JAVA_OPTIONS",
		"--add-opens=java.base/java.lang=ALL-UNNAMED", lim)
	found := false
	for _, h := range hits {
		if h.Reason == "deep-module-open" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected deep-module-open, got %+v", hits)
	}
	// 良性 add-opens（非 ALL-UNNAMED、非敏感包）不应报 deep。
	hits2 := auditOptionVariable("JDK_JAVA_OPTIONS",
		"--add-opens=java.desktop/java.awt=app", lim)
	for _, h := range hits2 {
		if h.Reason == "deep-module-open" {
			t.Fatalf("benign add-opens flagged: %+v", hits2)
		}
	}
}

func TestAuditOptionVariableLimits(t *testing.T) {
	lim := defaultEnvInjectionLimits()
	hits := auditOptionVariable("JAVA_TOOL_OPTIONS", repeat("a", lim.MaxVarValueLen+1), lim)
	if len(hits) != 1 || hits[0].Reason != "value-too-long" {
		t.Fatalf("expected value-too-long, got %+v", hits)
	}
	hits = auditOptionVariable("JAVA_TOOL_OPTIONS", "-Xmx2G\ncalc", lim)
	if len(hits) == 0 {
		t.Fatal("expected control-char hit")
	}
}

func TestSplitClasspathDriveColon(t *testing.T) {
	segs := splitClasspath(`C:\lib\a.jar;D:\b.jar`)
	if len(segs) != 2 {
		t.Fatalf("expected 2 segs, got %d: %v", len(segs), segs)
	}
	unix := splitClasspath("/opt/a.jar:/opt/b.jar")
	if len(unix) != 2 || unix[0] != "/opt/a.jar" {
		t.Fatalf("unix split wrong: %v", unix)
	}
}

func TestAuditEnvClasspath(t *testing.T) {
	lim := defaultEnvInjectionLimits()
	cases := []struct {
		val    string
		reason string
	}{
		{"a.jar;b.jar", ""},
		{`C:\a.jar;;D:\b.jar`, "empty-segment-cwd"},
		{"lib/*", "wildcard-segment"},
		{`lib\*`, "wildcard-segment"},
		{`\\srv\share\a.jar`, "unc-segment"},
		{"../evil/a.jar", "traversal-segment"},
	}
	for _, c := range cases {
		hits := auditEnvClasspath("CLASSPATH", c.val, lim)
		if c.reason == "" {
			if len(hits) != 0 {
				t.Fatalf("val %q expected clean, got %+v", c.val, hits)
			}
			continue
		}
		found := false
		for _, h := range hits {
			if h.Reason == c.reason {
				found = true
			}
		}
		if !found {
			t.Fatalf("val %q expected %s, got %+v", c.val, c.reason, hits)
		}
	}
}

func TestAuditEnvClasspathSegmentLimit(t *testing.T) {
	lim := defaultEnvInjectionLimits()
	var sb []byte
	for i := 0; i < lim.MaxClasspathN+1; i++ {
		if i > 0 {
			sb = append(sb, ';')
		}
		sb = append(sb, []byte("a.jar")...)
	}
	hits := auditEnvClasspath("CLASSPATH", string(sb), lim)
	if len(hits) != 1 || hits[0].Reason != "too-many-segments" {
		t.Fatalf("expected too-many-segments, got %+v", hits)
	}
}

func TestAuditJavaHome(t *testing.T) {
	lim := defaultEnvInjectionLimits()
	if h := auditJavaHome("JAVA_HOME", `C:\Java\jdk-21`, lim); len(h) != 0 {
		t.Fatalf("absolute drive should pass, got %+v", h)
	}
	if h := auditJavaHome("JAVA_HOME", `\\srv\jdk`, lim); len(h) == 0 || h[0].Reason != "unc-path" {
		t.Fatalf("expected unc-path, got %+v", h)
	}
	if h := auditJavaHome("JAVACMD", "%APPDATA%\\java.exe", lim); len(h) == 0 || h[0].Reason != "env-placeholder" {
		t.Fatalf("expected env-placeholder, got %+v", h)
	}
	if h := auditJavaHome("JAVA_HOME", "rel/jdk", lim); len(h) == 0 || h[0].Reason != "relative-path" {
		t.Fatalf("expected relative-path, got %+v", h)
	}
}

func TestAuditInheritedJVMClean(t *testing.T) {
	lim := defaultEnvInjectionLimits()
	v := AuditInheritedJVMEnv([]string{
		"PATH=/usr/bin",
		"HOME=/home/me",
		`JAVA_HOME=C:\Java\jdk`,
	}, lim)
	if !v.OK {
		t.Fatalf("clean env should pass, reason=%s hits=%+v", v.Reason, v.Hits)
	}
}

func TestAuditInheritedJVMAgentFails(t *testing.T) {
	lim := defaultEnvInjectionLimits()
	v := AuditInheritedJVMEnv([]string{
		"JAVA_TOOL_OPTIONS=-javaagent:evil.jar",
	}, lim)
	if v.OK {
		t.Fatal("expected fail on JAVA_TOOL_OPTIONS agent")
	}
	if v.Reason != "dangerous-option" {
		t.Fatalf("reason=%s", v.Reason)
	}
}

func TestAuditInheritedJVMPresentButBenignRecorded(t *testing.T) {
	lim := defaultEnvInjectionLimits()
	// 非空但内容良性：应判 OK（option-var-present 仅提示），但有一条提示命中。
	v := AuditInheritedJVMEnv([]string{
		"JAVA_TOOL_OPTIONS=-Xmx1G",
	}, lim)
	if !v.OK {
		t.Fatalf("benign option var should be OK, got %s", v.Reason)
	}
	saw := false
	for _, h := range v.Hits {
		if h.Reason == "option-var-present" {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("expected option-var-present hint, got %+v", v.Hits)
	}
}

func TestAuditInheritedJVMBadEntry(t *testing.T) {
	lim := defaultEnvInjectionLimits()
	v := AuditInheritedJVMEnv([]string{"NO_EQUALS_SIGN"}, lim)
	if v.OK || v.Reason != "bad-entry" {
		t.Fatalf("expected bad-entry, got ok=%v reason=%s", v.OK, v.Reason)
	}
}

func TestAuditInheritedJVMClasspathFails(t *testing.T) {
	lim := defaultEnvInjectionLimits()
	v := AuditInheritedJVMEnv([]string{
		"CLASSPATH=lib/*",
	}, lim)
	if v.OK || v.Reason != "wildcard-segment" {
		t.Fatalf("expected wildcard-segment, got ok=%v reason=%s", v.OK, v.Reason)
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
