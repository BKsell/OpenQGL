package main

import "testing"

func TestEICleanEnv(t *testing.T) {
	env := map[string]string{
		"APPDATA":  `C:\Users\me\AppData`,
		"USERNAME": "me",
		"TEMP":     `C:\Temp`,
	}
	if safe, _ := EIAuditEnv(env, ""); !safe {
		t.Fatal("ordinary env should inherit cleanly")
	}
}

func TestEIJavaToolOptions(t *testing.T) {
	env := map[string]string{"JAVA_TOOL_OPTIONS": "-Xmx2G"}
	_, fs := EIAuditEnv(env, "")
	if !EIHasReason(fs, EIReasonJVMOptionsOverride) {
		t.Fatalf("JAVA_TOOL_OPTIONS must not be inherited: %v", fs)
	}
}

func TestEIVariants(t *testing.T) {
	for _, n := range []string{"JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"} {
		env := map[string]string{n: "-x"}
		_, fs := EIAuditEnv(env, "")
		if !EIHasReason(fs, EIReasonJVMOptionsOverride) {
			t.Fatalf("%s must be controlled: %v", n, fs)
		}
	}
}

func TestEIClassPath(t *testing.T) {
	env := map[string]string{"CLASSPATH": `C:\evil\*`}
	_, fs := EIAuditEnv(env, "")
	if !EIHasReason(fs, EIReasonClassPathOverride) {
		t.Fatalf("CLASSPATH must not be bare inherited: %v", fs)
	}
}

func TestEIJavaHomeUntrusted(t *testing.T) {
	env := map[string]string{"JAVA_HOME": `C:\Attacker\jdk`}
	_, fs := EIAuditEnv(env, `C:\Trusted\jdk`)
	if !EIHasReason(fs, EIReasonJavaHomeOverride) {
		t.Fatalf("JAVA_HOME differing from trusted must flag: %v", fs)
	}
}

func TestEIJavaHomeTrustedOK(t *testing.T) {
	env := map[string]string{"JAVA_HOME": `C:\Trusted\jdk`}
	safe, _ := EIAuditEnv(env, `c:\trusted\jdk`)
	if !safe {
		t.Fatal("JAVA_HOME equal to the launcher's trusted JDK should pass")
	}
}

func TestEIAgentInArbitraryVar(t *testing.T) {
	env := map[string]string{"SOME_VAR": "opts=-javaagent:evil.jar"}
	_, fs := EIAuditEnv(env, "")
	if !EIHasReason(fs, EIReasonAgentLibInValue) {
		t.Fatalf("javaagent smuggled in any var must flag: %v", fs)
	}
}

func TestEISecretVar(t *testing.T) {
	env := map[string]string{"GITHUB_TOKEN": "ghp_x"}
	_, fs := EIAuditEnv(env, "")
	if !EIHasReason(fs, EIReasonSensitiveSecretPassthrough) {
		t.Fatalf("secret var must not flow to child: %v", fs)
	}
}

func TestEISanitizeStrips(t *testing.T) {
	env := map[string]string{
		"JAVA_TOOL_OPTIONS": "-x",
		"CLASSPATH":         "x",
		"APPDATA":           "keep",
	}
	clean := EISanitize(env)
	if _, ok := clean["JAVA_TOOL_OPTIONS"]; ok {
		t.Fatal("sanitize must drop JAVA_TOOL_OPTIONS")
	}
	if _, ok := clean["CLASSPATH"]; ok {
		t.Fatal("sanitize must drop CLASSPATH")
	}
	if _, ok := clean["APPDATA"]; !ok {
		t.Fatal("sanitize must keep ordinary vars")
	}
}
