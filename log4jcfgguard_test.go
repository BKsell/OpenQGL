package main

import "testing"

func l4cHas(fs []L4CFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestL4CAbsoluteFileConfig(t *testing.T) {
	pol := DefaultL4CPolicy()
	cfg := L4CConfigView{ConfigLocation: `file:///C:/mc/log4j2.xml`}
	safe, _ := L4CInspectProps(cfg, pol)
	if !safe {
		t.Fatal("absolute file: config should pass")
	}
}

func TestL4CRemoteHTTP(t *testing.T) {
	pol := DefaultL4CPolicy()
	cfg := L4CConfigView{ConfigLocation: "https://evil.test/log4j2.xml"}
	_, fs := L4CInspectProps(cfg, pol)
	if !l4cHas(fs, L4CReasonRemoteConfig) {
		t.Fatalf("want remote config, got %v", fs)
	}
}

func TestL4CBareName(t *testing.T) {
	pol := DefaultL4CPolicy()
	cfg := L4CConfigView{ConfigLocation: "log4j2.xml"}
	_, fs := L4CInspectProps(cfg, pol)
	if !l4cHas(fs, L4CReasonRelativeConfig) {
		t.Fatalf("want relative/bare config, got %v", fs)
	}
}

func TestL4CWritableConfig(t *testing.T) {
	pol := DefaultL4CPolicy()
	cfg := L4CConfigView{ConfigLocation: `file:///C:/mc/log4j2.xml`, ConfigWritable: true}
	_, fs := L4CInspectProps(cfg, pol)
	if !l4cHas(fs, L4CReasonWritableConfig) {
		t.Fatalf("want writable config, got %v", fs)
	}
}

func TestL4CLookupsEnabled(t *testing.T) {
	pol := DefaultL4CPolicy()
	cfg := L4CConfigView{ConfigLocation: `file:///C:/mc/log4j2.xml`, LookupsEnabled: true}
	_, fs := L4CInspectProps(cfg, pol)
	if !l4cHas(fs, L4CReasonLookupsEnabled) {
		t.Fatalf("want lookups enabled, got %v", fs)
	}
}

func TestL4CJndiEnabled(t *testing.T) {
	pol := DefaultL4CPolicy()
	cfg := L4CConfigView{ConfigLocation: `file:///C:/mc/log4j2.xml`, JndiEnabled: true}
	_, fs := L4CInspectProps(cfg, pol)
	if !l4cHas(fs, L4CReasonJndiLookupEnabled) {
		t.Fatalf("want jndi lookup enabled, got %v", fs)
	}
}

func TestL4CJarScheme(t *testing.T) {
	pol := DefaultL4CPolicy()
	_, fs := L4CInspectProps(L4CConfigView{ConfigLocation: "jar:file:///x.jar!/log4j2.xml"}, pol)
	if !l4cHas(fs, L4CReasonRemoteConfig) {
		t.Fatalf("want jar scheme flagged remote, got %v", fs)
	}
}

func TestL4CConfigJndiContent(t *testing.T) {
	pol := DefaultL4CPolicy()
	xml := `<Configuration><Appenders><JNDI name="x" javaNamingFactoryURL="ldap://evil/a"/></Appenders></Configuration>`
	_, fs := L4CInspectConfigText(xml, pol)
	if !l4cHas(fs, L4CReasonJNDIInConfig) {
		t.Fatalf("want jndi in config, got %v", fs)
	}
}

func TestL4CConfigScriptContent(t *testing.T) {
	pol := DefaultL4CPolicy()
	xml := `<Configuration><Appenders><Script name="x" language="groovy">Runtime...</Script></Appenders></Configuration>`
	_, fs := L4CInspectConfigText(xml, pol)
	if !l4cHas(fs, L4CReasonScriptInConfig) {
		t.Fatalf("want script appender, got %v", fs)
	}
}

func TestL4CConfigJdbcContent(t *testing.T) {
	pol := DefaultL4CPolicy()
	xml := `<Configuration><Appenders><JDBC name="db"><ConnectionFactory class="..."/></JDBC></Appenders></Configuration>`
	_, fs := L4CInspectConfigText(xml, pol)
	if !l4cHas(fs, L4CReasonScriptInConfig) {
		t.Fatalf("want jdbc appender, got %v", fs)
	}
}

func TestL4CConfigClean(t *testing.T) {
	pol := DefaultL4CPolicy()
	xml := `<Configuration><Appenders><Console name="stdout"><PatternLayout pattern="%msg%n"/></Console></Appenders></Configuration>`
	safe, _ := L4CInspectConfigText(xml, pol)
	if !safe {
		t.Fatal("plain console config should be safe")
	}
}

func TestL4CScriptAllowedByPolicy(t *testing.T) {
	pol := DefaultL4CPolicy()
	pol.AllowScriptAppenders = true
	xml := `<Configuration><Appenders><Script name="x">code</Script></Appenders></Configuration>`
	safe, _ := L4CInspectConfigText(xml, pol)
	if !safe {
		t.Fatal("script allowed by policy should pass")
	}
}
