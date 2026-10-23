package main

import "testing"

func jvlHas(fs []JVLFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestJVLNormalLaunch(t *testing.T) {
	pol := DefaultJVLPolicy()
	args := []string{"-Xmx2G", "-Xms512M", "-Djava.awt.headless=false",
		"-cp", `C:\mc\libraries\a.jar;C:\mc\client.jar`,
		"net.minecraft.client.main.Main", "--username", "tester"}
	safe, _ := JVLValidate(args, nil, pol)
	if !safe {
		t.Fatal("normal client launch should pass")
	}
}

func TestJVLAgentBlocked(t *testing.T) {
	pol := DefaultJVLPolicy()
	_, fs := JVLValidate([]string{"-javaagent:evil.jar", "net.minecraft.client.main.Main"}, nil, pol)
	if !jvlHas(fs, JVLReasonJavaAgent) {
		t.Fatalf("want javaagent, got %v", fs)
	}
}

func TestJVLAgentLibBlocked(t *testing.T) {
	pol := DefaultJVLPolicy()
	_, fs := JVLValidate([]string{"-agentpath:C:\\hack.dll", "net.minecraft.client.main.Main"}, nil, pol)
	if !jvlHas(fs, JVLReasonAgentLib) {
		t.Fatalf("want agentlib, got %v", fs)
	}
}

func TestJVLBootClasspath(t *testing.T) {
	pol := DefaultJVLPolicy()
	_, fs := JVLValidate([]string{"-Xbootclasspath/a:evil.jar", "net.minecraft.client.main.Main"}, nil, pol)
	if !jvlHas(fs, JVLReasonBootClasspath) {
		t.Fatalf("want bootclasspath, got %v", fs)
	}
}

func TestJVLAddOpens(t *testing.T) {
	pol := DefaultJVLPolicy()
	_, fs := JVLValidate([]string{"--add-opens=java.base/java.lang=ALL-UNNAMED",
		"net.minecraft.client.main.Main"}, nil, pol)
	if !jvlHas(fs, JVLReasonAddOpensAll) {
		t.Fatalf("want add-opens, got %v", fs)
	}
}

func TestJVLLibraryPath(t *testing.T) {
	pol := DefaultJVLPolicy()
	_, fs := JVLValidate([]string{"-Djava.library.path=C:\\evil", "net.minecraft.client.main.Main"}, nil, pol)
	if !jvlHas(fs, JVLReasonLibraryPath) {
		t.Fatalf("want library path, got %v", fs)
	}
}

func TestJVLClasspathWildcard(t *testing.T) {
	pol := DefaultJVLPolicy()
	_, fs := JVLValidate([]string{"-cp", `C:\mc\mods\*`, "net.minecraft.client.main.Main"}, nil, pol)
	if !jvlHas(fs, JVLReasonClasspathWildcard) {
		t.Fatalf("want wildcard, got %v", fs)
	}
}

func TestJVLClasspathRelative(t *testing.T) {
	pol := DefaultJVLPolicy()
	_, fs := JVLValidate([]string{"-cp", "libs/a.jar;client.jar", "net.minecraft.client.main.Main"}, nil, pol)
	if !jvlHas(fs, JVLReasonClasspathRelative) {
		t.Fatalf("want relative cp, got %v", fs)
	}
}

func TestJVLUnexpectedMain(t *testing.T) {
	pol := DefaultJVLPolicy()
	_, fs := JVLValidate([]string{"com.evil.Main"}, nil, pol)
	if !jvlHas(fs, JVLReasonUnexpectedMain) {
		t.Fatalf("want unexpected main, got %v", fs)
	}
}

func TestJVLDashJarBlocked(t *testing.T) {
	pol := DefaultJVLPolicy()
	_, fs := JVLValidate([]string{"-jar", "unknown.jar"}, nil, pol)
	if !jvlHas(fs, JVLReasonDashJar) {
		t.Fatalf("want dashjar, got %v", fs)
	}
}

func TestJVLRemoteDebug(t *testing.T) {
	pol := DefaultJVLPolicy()
	_, fs := JVLValidate([]string{"-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005",
		"net.minecraft.client.main.Main"}, nil, pol)
	if !jvlHas(fs, JVLReasonEnableAssertions) {
		t.Fatalf("want remote debug, got %v", fs)
	}
}

func TestJVLProxyProp(t *testing.T) {
	pol := DefaultJVLPolicy()
	_, fs := JVLValidate([]string{"-Dhttps.proxyHost=10.0.0.9", "net.minecraft.client.main.Main"}, nil, pol)
	if !jvlHas(fs, JVLReasonDangerousProp) {
		t.Fatalf("want proxy prop, got %v", fs)
	}
}

func TestJVLEnvInjection(t *testing.T) {
	pol := DefaultJVLPolicy()
	env := map[string]string{"JAVA_TOOL_OPTIONS": "-javaagent:pwn.jar"}
	_, fs := JVLValidate([]string{"net.minecraft.client.main.Main"}, env, pol)
	if !jvlHas(fs, JVLReasonEnvInjection) {
		t.Fatalf("want env injection, got %v", fs)
	}
}

func TestJVLClasspathSplitDrive(t *testing.T) {
	entries := jvlClasspathEntries(`C:\a.jar;D:\b.jar`)
	if len(entries) != 2 || entries[0] != `C:\a.jar` || entries[1] != `D:\b.jar` {
		t.Fatalf("drive split wrong: %#v", entries)
	}
}

func TestJVLAgentAllowedByPolicy(t *testing.T) {
	pol := DefaultJVLPolicy()
	pol.AllowAgents = true
	safe, _ := JVLValidate([]string{"-javaagent:ok.jar", "net.minecraft.client.main.Main"}, nil, pol)
	if !safe {
		t.Fatal("agent allowed by policy should pass")
	}
}
