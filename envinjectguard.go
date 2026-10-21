package main

// envinjectguard.go —— 继承环境中的“带外 JVM 注入”审计内核。
//
// 与 envbudget 的分工：envbudget 审计“启动器准备额外透传”的环境变量集合的
// 总量/键名/值字符；它不解析值内容，也不覆盖“子进程默认从父进程继承”的那
// 部分（os.Environ()）。Java 进程在读取命令行参数之前，会先吃进若干环境
// 变量里的 JVM 选项，这是一条不经过命令行、因此能绕过 jvmargs/jvmprops
// 命令行守卫的注入通道：
//
//	JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS / _JAVA_OPTIONS
//	IBM_JAVA_OPTIONS / OPENJ9_JAVA_OPTIONS
//
// 里面可以塞 -javaagent:x.jar（任意字节码注入）、-Xverify:none（关闭字节码
// 校验）、--add-opens=java.base/java.lang=ALL-UNNAMED（深度反射）、
// -Djavax.net.ssl.trustStore=…（换根证书）等；CLASSPATH 里的空段表示
// “当前目录”，通配符段表示整个目录，都是类劫持入口；JAVA_HOME/JAVACMD
// 决定实际使用哪个 java 可执行文件。
//
// 本模块对“合并后、即将被子进程继承”的完整环境做值内容审计，纯函数、
// 不读真实进程环境、不发起任何 IO，全部判定可穷举测试。

import (
	"strings"
)

// EnvInjectionLimits 继承环境审计的量化边界。
type EnvInjectionLimits struct {
	MaxVarValueLen int
	MaxClasspathN  int
	MaxTokenLen    int
}

func defaultEnvInjectionLimits() EnvInjectionLimits {
	return EnvInjectionLimits{
		MaxVarValueLen: 8192,
		MaxClasspathN:  64,
		MaxTokenLen:    1024,
	}
}

// optionInjectionVars：值会被 JVM 当作额外启动选项解析的环境变量（大写匹配）。
var optionInjectionVars = []string{
	"JAVA_TOOL_OPTIONS",
	"JDK_JAVA_OPTIONS",
	"_JAVA_OPTIONS",
	"IBM_JAVA_OPTIONS",
	"OPENJ9_JAVA_OPTIONS",
}

// pathCarryingVars：值指向可执行文件 / 库 / 类搜索路径的环境变量。
var pathCarryingVars = []string{
	"JAVA_HOME", "JRE_HOME", "JAVACMD", "JAVA_CMD",
	"CLASSPATH", "JAVA_CLASS_PATH",
}

// 出现在选项变量里即视为高危的 token 前缀（小写匹配前缀）。
var dangerousOptionTokens = []string{
	"-javaagent:",
	"-agentlib:",
	"-agentpath:",
	"-xverify:none",
	"-noverify",
	"-xbootclasspath:",
	"-xbootclasspath/a:",
	"-xbootclasspath/p:",
	"-djdk.attach.allowattachself=true",
	"-dcom.sun.management.jmxremote.port=",
	"-dcom.sun.management.jmxremote.ssl=false",
	"-djavax.net.ssl.truststore=",
	"-djavax.net.ssl.keystore=",
	"-dlog4j.configurationfile=",
	"-dlog4j2.configurationfile=",
	"-djava.endorsed.dirs=",
	"-djava.ext.dirs=",
	"-dsecurerandom.source=",
}

// 出现在选项变量里、需要进一步看开放目标的 --add-opens/--add-exports 形态。
const addOpensAllUnnamed = "--add-opens="
const addExportsAllUnnamed = "--add-exports="

type envInjectionHit struct {
	Var    string
	Token  string
	Reason string
}

type envInjectionVerdict struct {
	OK      bool
	Reason  string
	Hits    []envInjectionHit
	Scanned int
}

// splitOptionTokens 按空白拆分 JVM 选项字符串，感知成对双引号（JVM 环境变量
// 支持引号包住含空格的路径）。不做任何转义展开。
func splitOptionTokens(value string) []string {
	tokens := []string{}
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for _, r := range value {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t' || r == '\n' || r == '\r') && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return tokens
}

func upperEnvKey(item string) (key, val string, ok bool) {
	eq := strings.IndexByte(item, '=')
	if eq <= 0 {
		return "", "", false
	}
	return strings.ToUpper(item[:eq]), item[eq+1:], true
}

func envValueHasControlChar(val string) bool {
	for _, r := range val {
		if r < 32 && r != 9 {
			return true
		}
	}
	return false
}

// auditOptionVariable 审计 JAVA_TOOL_OPTIONS 一类变量的值。
func auditOptionVariable(varName, val string, lim EnvInjectionLimits) []envInjectionHit {
	hits := []envInjectionHit{}
	if val == "" {
		return hits
	}
	if len(val) > lim.MaxVarValueLen {
		return []envInjectionHit{{Var: varName, Reason: "value-too-long"}}
	}
	if envValueHasControlChar(val) {
		return []envInjectionHit{{Var: varName, Reason: "control-char"}}
	}
	for _, tok := range splitOptionTokens(val) {
		if len(tok) > lim.MaxTokenLen {
			hits = append(hits, envInjectionHit{Var: varName, Token: truncateTok(tok), Reason: "token-too-long"})
			continue
		}
		lower := strings.ToLower(tok)
		for _, bad := range dangerousOptionTokens {
			if strings.HasPrefix(lower, bad) {
				hits = append(hits, envInjectionHit{Var: varName, Token: truncateTok(tok), Reason: "dangerous-option"})
				break
			}
		}
		if strings.HasPrefix(lower, addOpensAllUnnamed) || strings.HasPrefix(lower, addExportsAllUnnamed) {
			target := lower
			if i := strings.IndexByte(target, '='); i >= 0 {
				target = target[i+1:]
			}
			if strings.HasSuffix(target, "=all-unnamed") || strings.Contains(target, "java.lang") || strings.Contains(target, "java.lang.reflect") {
				hits = append(hits, envInjectionHit{Var: varName, Token: truncateTok(tok), Reason: "deep-module-open"})
			}
		}
	}
	return hits
}

func truncateTok(t string) string {
	if len(t) <= 128 {
		return t
	}
	return t[:128] + "..."
}

// auditEnvClasspath 审计 CLASSPATH：拆段、拒空段（当前目录）、拒通配符段、
// 拒 UNC/盘符穿越/控制字符。跨平台分隔符 ; 与 : 都拆（Java 在两平台只
// 认一个，但继承环境不可信，从严两个都拆）。
func auditEnvClasspath(varName, val string, lim EnvInjectionLimits) []envInjectionHit {
	hits := []envInjectionHit{}
	if val == "" {
		return hits
	}
	if len(val) > lim.MaxVarValueLen {
		return []envInjectionHit{{Var: varName, Reason: "value-too-long"}}
	}
	segments := splitClasspath(val)
	if len(segments) > lim.MaxClasspathN {
		return []envInjectionHit{{Var: varName, Reason: "too-many-segments"}}
	}
	for _, seg := range segments {
		switch {
		case seg == "":
			hits = append(hits, envInjectionHit{Var: varName, Reason: "empty-segment-cwd"})
		case seg == "*" || strings.HasSuffix(seg, `\*`) || strings.HasSuffix(seg, "/*"):
			hits = append(hits, envInjectionHit{Var: varName, Token: truncateTok(seg), Reason: "wildcard-segment"})
		case strings.HasPrefix(seg, `\\`) || strings.HasPrefix(seg, "//"):
			hits = append(hits, envInjectionHit{Var: varName, Token: truncateTok(seg), Reason: "unc-segment"})
		case seg == ".." || strings.Contains(seg, `..\`) || strings.Contains(seg, "../"):
			hits = append(hits, envInjectionHit{Var: varName, Token: truncateTok(seg), Reason: "traversal-segment"})
		case envValueHasControlChar(seg):
			hits = append(hits, envInjectionHit{Var: varName, Token: truncateTok(seg), Reason: "control-char"})
		}
	}
	return hits
}

func splitClasspath(val string) []string {
	segs := []string{}
	cur := strings.Builder{}
	flush := func() {
		segs = append(segs, cur.String())
		cur.Reset()
	}
	runes := []rune(val)
	for i, r := range runes {
		if r == ';' {
			flush()
			continue
		}
		// ':' 在 Windows 盘符位置（C:\ / C:/）时不是 classpath 分隔符。
		if r == ':' {
			if !(i >= 1 && i+1 < len(runes) &&
				((runes[i-1] >= 'A' && runes[i-1] <= 'Z') || (runes[i-1] >= 'a' && runes[i-1] <= 'z')) &&
				(runes[i+1] == '\\' || runes[i+1] == '/')) {
				flush()
				continue
			}
		}
		cur.WriteRune(r)
	}
	flush()
	return segs
}

// auditJavaHome 审计指向 Java 可执行文件 / 安装目录的变量。
func auditJavaHome(varName, val string, lim EnvInjectionLimits) []envInjectionHit {
	if val == "" {
		return nil
	}
	hits := []envInjectionHit{}
	if len(val) > lim.MaxVarValueLen {
		return []envInjectionHit{{Var: varName, Reason: "value-too-long"}}
	}
	if envValueHasControlChar(val) {
		return []envInjectionHit{{Var: varName, Reason: "control-char"}}
	}
	up := strings.ToUpper(val)
	switch {
	case strings.HasPrefix(val, `\\`) || strings.HasPrefix(val, "//"):
		hits = append(hits, envInjectionHit{Var: varName, Token: truncateTok(val), Reason: "unc-path"})
	case len(val) >= 3 && val[1] == ':' && (val[2] == '\\' || val[2] == '/'):
		// 盘符绝对路径：本身合法，但若带穿越段仍拒绝。
		if strings.Contains(val, "..") {
			hits = append(hits, envInjectionHit{Var: varName, Token: truncateTok(val), Reason: "traversal-path"})
		}
	case strings.Contains(up, "%") || strings.Contains(val, "${") || strings.Contains(val, "~"):
		hits = append(hits, envInjectionHit{Var: varName, Token: truncateTok(val), Reason: "env-placeholder"})
	case !isAbsoluteASCII(val):
		hits = append(hits, envInjectionHit{Var: varName, Token: truncateTok(val), Reason: "relative-path"})
	}
	return hits
}

// isAbsoluteASCII 只识别明确的绝对形态（盘符或前导斜杠），其余按相对拒绝。
func isAbsoluteASCII(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0]
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	}
	return false
}

// AuditInheritedJVMEnv 审计合并后、将被子进程继承的完整环境（KEY=value 列表）。
// 任一高危命中即 OK=false；Hits 收集全部命中（不止首个），便于审计展示。
func AuditInheritedJVMEnv(env []string, lim EnvInjectionLimits) envInjectionVerdict {
	if lim.MaxVarValueLen == 0 {
		lim = defaultEnvInjectionLimits()
	}
	v := envInjectionVerdict{OK: true}
	seenOptionVar := map[string]bool{}
	for _, item := range env {
		key, val, ok := upperEnvKey(item)
		if !ok {
			v.OK = false
			v.Reason = "bad-entry"
			v.Hits = append(v.Hits, envInjectionHit{Reason: "bad-entry"})
			return v
		}
		v.Scanned++

		if inStringSlice(optionInjectionVars, key) {
			// 同一变量出现多次（不同大小写）本身就是环境污染信号。
			if seenOptionVar[key] {
				v.Hits = append(v.Hits, envInjectionHit{Var: key, Reason: "duplicate-option-var"})
			}
			seenOptionVar[key] = true
			// 只要这些“带外选项”变量存在且非空，即使内容暂未命中黑名单，
			// 也记录为存在带外通道（调用方可按策略告警或清空）。
			if val != "" {
				v.Hits = append(v.Hits, auditOptionVariable(key, val, lim)...)
				if !hasHitFor(v.Hits, key) {
					v.Hits = append(v.Hits, envInjectionHit{Var: key, Reason: "option-var-present"})
				}
			}
			continue
		}

		switch key {
		case "CLASSPATH", "JAVA_CLASS_PATH":
			v.Hits = append(v.Hits, auditEnvClasspath(key, val, lim)...)
		case "JAVA_HOME", "JRE_HOME", "JAVACMD", "JAVA_CMD":
			v.Hits = append(v.Hits, auditJavaHome(key, val, lim)...)
		}
	}

	for _, h := range v.Hits {
		// option-var-present 属提示级（由调用方决定），其余全部判失败。
		if h.Reason != "option-var-present" {
			v.OK = false
			if v.Reason == "" {
				v.Reason = h.Reason
			}
		}
	}
	return v
}

func inStringSlice(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func hasHitFor(hits []envInjectionHit, varName string) bool {
	for _, h := range hits {
		if h.Var == varName && h.Reason != "option-var-present" {
			return true
		}
	}
	return false
}
