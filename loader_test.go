package main

import "testing"

// TestIsAllowedMavenLibURL_Trusted 官方与镜像 Maven 主机必须放行（重写前后都可能出现）。
func TestIsAllowedMavenLibURL_Trusted(t *testing.T) {
	good := []string{
		"https://maven.minecraftforge.net/net/minecraftforge/forge/1.20.1/forge-1.20.1.jar",
		"https://maven.neoforged.net/releases/net/neoforged/neoforge/21.0.0/neoforge-21.0.0.jar",
		"https://libraries.minecraft.net/com/mojang/logging/1.0.0/logging-1.0.0.jar",
		"https://piston-data.mojang.com/v1/objects/abc/client.jar",
		"https://maven.fabricmc.net/net/fabricmc/fabric-loader/0.15.0/fabric-loader-0.15.0.jar",
		"https://repo1.maven.org/maven2/org/ow2/asm/asm/9.6/asm-9.6.jar",
		"https://bmclapi2.bangbang93.com/maven/net/minecraftforge/forge/a.jar",
	}
	for _, u := range good {
		if !isAllowedMavenLibURL(u) {
			t.Errorf("可信 Maven URL 被误拒: %s", u)
		}
	}
}

// TestIsAllowedMavenLibURL_Malicious 攻击者可控主机/协议必须全部拒绝。
func TestIsAllowedMavenLibURL_Malicious(t *testing.T) {
	bad := []string{
		"http://maven.minecraftforge.net/x.jar",                              // 非 https
		"https://evil.example/x.jar",                                         // 不在白名单
		"https://maven.minecraftforge.net.evil.com/x.jar",                    // 后缀伪造子域
		"https://evilmaven.minecraftforge.net/x.jar",                         // 伪造子域（精确匹配拦截）
		"https://user:pass@bmclapi2.bangbang93.com/x.jar",                    // userinfo
		"https://bmclapi2.bangbang93.com:8443/x.jar",                         // 非标准端口
		"https://bmclapi2.bangbang93.com@evil.com/x.jar",                     // 视觉混淆
		"javascript:alert(1)",                                                // 非 http(s)
		"",                                                                   // 空
		"https://repo1.maven.org.evil.tld/x.jar",                             // 结尾前接伪域
		"   ",                                                                // 纯空白
	}
	for _, u := range bad {
		if isAllowedMavenLibURL(u) {
			t.Errorf("危险 Maven URL 必须被拒绝，但被放行: %q", u)
		}
	}
}

// TestIsAllowedMavenLibURL_TrailingDot 结尾点的主机名规范化后仍须精确命中。
func TestIsAllowedMavenLibURL_TrailingDot(t *testing.T) {
	if !isAllowedMavenLibURL("https://repo1.maven.org./maven2/x/y.jar") {
		t.Error("合法的结尾点主机名应被规范化后放行")
	}
	if isAllowedMavenLibURL("https://evil.com./x.jar") {
		t.Error("非白名单主机即使带结尾点也必须拒绝")
	}
}

// TestIsSafeRelPath 锁定安装器内相对路径的 Zip Slip 判定（跨平台一致的遍历用例）。
func TestIsSafeRelPath(t *testing.T) {
	if got := isSafeRelPath("net/minecraftforge/forge/a.jar"); got != "net/minecraftforge/forge/a.jar" {
		t.Errorf("正常 maven 路径被误判: %q", got)
	}
	if got := isSafeRelPath("./a.jar"); got != "a.jar" {
		t.Errorf("./ 前缀应被 Clean: %q", got)
	}
	bad := []string{
		"",
		"../evil.jar",
		"a/../../evil.jar",
		"a/b/../../../etc/passwd",
		"mods/../../../windows/system32",
	}
	for _, in := range bad {
		if got := isSafeRelPath(in); got != "" {
			t.Errorf("危险相对路径 %q 必须返回空串，got %q", in, got)
		}
	}
}
