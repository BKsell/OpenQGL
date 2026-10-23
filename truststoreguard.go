package main

// truststoreguard.go —— JVM 信任库（trustStore）与自定义 X509TrustManager 注入守卫。
//
// 背景：
//   启动器在需要对接自建 Yggdrasil 皮肤站、走企业代理或抓包调试时，可能给 JVM/HTTP 栈设置
//   自定义信任材料。几个高危写法会让"信任锚"被替换，从而静默信任任意证书：
//     - -Djavax.net.ssl.trustStore=<路径> 指向可写/相对/用户可控的库文件；
//     - -Djavax.net.ssl.trustStorePassword= 把口令放到命令行（配合 argspillguard）；
//     - -Djavax.net.ssl.trustStoreType= 换成弱类型，或 trustStoreNUL 旁路；
//     - 代码层安装"全信任 TrustManager"（getAcceptedIssuers 返回空、checkServerTrusted 空实现）；
//     - SSLContext 初始化时用了这种 permissive manager，等价于 InsecureSkipVerify。
//   本模块审查"信任库配置视图 + 系统属性"，并对一个逻辑 TrustManager 行为描述做判定，
//   纯字符串/布尔判定，不使用正则。

import "strings"

const (
	TSTReasonTrustStorePath        = "truststore-writable-or-relative-path"
	TSTReasonTrustStorePasswordArg = "truststore-password-on-command-line"
	TSTReasonTrustStoreTypeWeak    = "truststore-weak-or-null-type"
	TSTReasonPermissiveManager     = "truststore-permissive-x509trustmanager"
	TSTReasonEmptyAcceptedIssuers  = "truststore-empty-accepted-issuers"
	TSTReasonCheckTrustedNoop      = "truststore-checkservertrusted-noop"
	TSTReasonPermissiveSSLContext  = "truststore-permissive-sslcontext-installed"
	TSTReasonTrustAllProp          = "truststore-trust-all-system-property"
)

// TSTPolicy 控制信任库要求。
type TSTPolicy struct {
	RequireAbsoluteStorePath bool
	ForbidPasswordOnArgs     bool
	AllowCustomStoreType     bool
	AcceptedStoreTypes       map[string]bool
}

// TSTFinding 记录一处信任库风险。
type TSTFinding struct {
	Reason string
	Detail string
}

// TSTStoreView 描述 javax.net.ssl.trustStore 相关配置。
type TSTStoreView struct {
	StorePath     string // -Djavax.net.ssl.trustStore 值；空表示用 JDK 默认
	StoreType     string // -Djavax.net.ssl.trustStoreType
	PasswordOnArg bool   // 口令是否出现在命令行属性里
	PathExists    bool
	PathWritable  bool // 信任库文件是否对普通用户可写（可被替换）
}

// TSTManagerView 描述代码层 TrustManager 行为。
type TSTManagerView struct {
	GetAcceptedIssuersEmpty bool
	CheckClientTrustedNoop  bool
	CheckServerTrustedNoop  bool
	InstalledIntoSSLContext bool
}

// DefaultTSTPolicy 返回默认策略。
func DefaultTSTPolicy() TSTPolicy {
	return TSTPolicy{
		RequireAbsoluteStorePath: true,
		ForbidPasswordOnArgs:     true,
		AllowCustomStoreType:     false,
		AcceptedStoreTypes:       map[string]bool{"JKS": true, "PKCS12": true},
	}
}

// tstIsAbsPath 判断是否为绝对路径（Windows 盘符/UNC 或 POSIX /）。
func tstIsAbsPath(p string) bool {
	if p == "" {
		return false
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") {
		return true
	}
	return p[0] == '/'
}

// TSTInspectSystemProps 扫描 JVM 系统属性键值，识别信任库相关注入。
func TSTInspectSystemProps(props map[string]string, policy TSTPolicy) (safe bool, findings []TSTFinding) {
	for k, v := range props {
		key := strings.ToLower(strings.TrimSpace(k))
		switch key {
		case "javax.net.ssl.truststore":
			if v != "" {
				if policy.RequireAbsoluteStorePath && !tstIsAbsPath(v) {
					findings = append(findings, TSTFinding{Reason: TSTReasonTrustStorePath, Detail: "relative"})
				}
			}
		case "javax.net.ssl.truststorepassword":
			if strings.TrimSpace(v) != "" {
				findings = append(findings, TSTFinding{Reason: TSTReasonTrustStorePasswordArg})
			}
		case "javax.net.ssl.truststoretype":
			t := strings.ToUpper(strings.TrimSpace(v))
			if t == "" || t == "NONE" {
				findings = append(findings, TSTFinding{Reason: TSTReasonTrustStoreTypeWeak, Detail: "NONE"})
			} else if !policy.AcceptedStoreTypes[t] && !policy.AllowCustomStoreType {
				findings = append(findings, TSTFinding{Reason: TSTReasonTrustStoreTypeWeak, Detail: t})
			}
		}
		// 一些库的"信任所有"开关
		if strings.Contains(key, "trustall") || strings.Contains(key, "trust-all") ||
			strings.Contains(key, "disablecertvalidation") {
			if strings.EqualFold(strings.TrimSpace(v), "true") || v == "1" {
				findings = append(findings, TSTFinding{Reason: TSTReasonTrustAllProp, Detail: key})
			}
		}
	}
	return len(findings) == 0, findings
}

// TSTInspectStore 校验信任库文件视图。
func TSTInspectStore(store TSTStoreView, policy TSTPolicy) (safe bool, findings []TSTFinding) {
	if store.StorePath != "" {
		if policy.RequireAbsoluteStorePath && !tstIsAbsPath(store.StorePath) {
			findings = append(findings, TSTFinding{Reason: TSTReasonTrustStorePath, Detail: "relative"})
		}
		if store.PathExists && store.PathWritable {
			findings = append(findings, TSTFinding{Reason: TSTReasonTrustStorePath, Detail: "world-writable"})
		}
	}
	if policy.ForbidPasswordOnArgs && store.PasswordOnArg {
		findings = append(findings, TSTFinding{Reason: TSTReasonTrustStorePasswordArg})
	}
	t := strings.ToUpper(strings.TrimSpace(store.StoreType))
	if store.StorePath != "" {
		if t == "" || t == "NONE" {
			findings = append(findings, TSTFinding{Reason: TSTReasonTrustStoreTypeWeak, Detail: "NONE"})
		} else if !policy.AcceptedStoreTypes[t] && !policy.AllowCustomStoreType {
			findings = append(findings, TSTFinding{Reason: TSTReasonTrustStoreTypeWeak, Detail: t})
		}
	}
	return len(findings) == 0, findings
}

// TSTInspectManager 校验自定义 TrustManager 是否为"全信任"实现。
func TSTInspectManager(mgr TSTManagerView) (safe bool, findings []TSTFinding) {
	permissive := mgr.GetAcceptedIssuersEmpty || mgr.CheckServerTrustedNoop || mgr.CheckClientTrustedNoop
	if mgr.GetAcceptedIssuersEmpty {
		findings = append(findings, TSTFinding{Reason: TSTReasonEmptyAcceptedIssuers})
	}
	if mgr.CheckServerTrustedNoop {
		findings = append(findings, TSTFinding{Reason: TSTReasonCheckTrustedNoop, Detail: "server"})
	}
	if mgr.CheckClientTrustedNoop {
		findings = append(findings, TSTFinding{Reason: TSTReasonCheckTrustedNoop, Detail: "client"})
	}
	if permissive {
		findings = append(findings, TSTFinding{Reason: TSTReasonPermissiveManager})
		if mgr.InstalledIntoSSLContext {
			findings = append(findings, TSTFinding{Reason: TSTReasonPermissiveSSLContext})
		}
	}
	return len(findings) == 0, findings
}
