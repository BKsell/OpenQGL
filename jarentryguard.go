package main

// jarentryguard.go —— Mod/依赖 jar（zip）内部条目安全守卫。
//
// 背景：
//   启动器安装 Fabric/Forge/模组时要解包或加载 jar。jar 本质是 zip，其内部条目名同样可控：
//     - Zip Slip：条目名 ../、绝对路径，解包越出目标目录（tarslipguard 管 tar，这里按 jar 条目再核）；
//     - 重复条目：同名 entry 出现两次，不同 zip 读取器取"第一个/最后一个"不一致，可让签名清单覆盖
//       的类与实际加载的类不符（签名绕过/差异攻击）；
//     - META-INF 篡改：模组 jar 自带 META-INF/*.SF/.RSA/.DSA 或签名索引，可能伪造/与官方库冲突；
//     - 服务注入：META-INF/services/ 下注册危险接口实现（SPI 注入），被 classpath 上其它组件加载；
//     - 覆盖引导类：条目路径伪装成 java/、javax/、META-INF/versions 多发行版本（multi-release）降级；
//     - 可执行/脚本条目（.bat/.cmd/.exe/.dll/.sh/.jnlp）混进资源目录；
//     - 大小写不同的同名类（Foo.class 与 foo.class）在大小写不敏感文件系统互相覆盖。
//   本模块对 jar 条目清单做审计，纯字符串处理，不使用正则。

import "strings"

const (
	JEGReasonSlipPath          = "jarentry-path-traversal"
	JEGReasonAbsoluteEntry     = "jarentry-absolute-path"
	JEGReasonDuplicateEntry    = "jarentry-duplicate-member"
	JEGReasonCaseCollision     = "jarentry-case-insensitive-collision"
	JEGReasonSignatureArtifact = "jarentry-bundled-code-signing-artifact"
	JEGReasonServiceInject     = "jarentry-spi-service-registration"
	JEGReasonBootClassPath     = "jarentry-boot-classpath-package-override"
	JEGReasonExecutableMember  = "jarentry-executable-or-script-member"
	JEGReasonMultiRelease      = "jarentry-multi-release-override"
)

// JEGEntry 是 jar 内一个条目。
type JEGEntry struct {
	Name  string // 原始条目名，使用 / 分隔
	Size  int64
	IsDir bool
}

// JEGPolicy 设定 jar 审计策略。
type JEGPolicy struct {
	ForbidSignatureArtifacts bool
	ForbidServiceFiles       bool
	AllowMultiRelease        bool
	AllowedExecutableExt     map[string]bool
}

// JEGFinding 记录一处 jar 条目风险。
type JEGFinding struct {
	Reason string
	Entry  string
	Detail string
}

// DefaultJEGPolicy 对"来自第三方模组源"的 jar 采取严格策略。
func DefaultJEGPolicy() JEGPolicy {
	return JEGPolicy{
		ForbidSignatureArtifacts: true,
		ForbidServiceFiles:       false, // 登记告警但不默认禁（部分模组正当使用 SPI）
		AllowMultiRelease:        false,
		AllowedExecutableExt:     map[string]bool{},
	}
}

// jegExt 取小写扩展名。
func jegExt(name string) string {
	for i := len(name) - 1; i >= 0 && name[i] != '/'; i-- {
		if name[i] == '.' {
			return strings.ToLower(name[i:])
		}
	}
	return ""
}

// JEGAudit 审计全部 jar 条目。
func JEGAudit(entries []JEGEntry, policy JEGPolicy) (safe bool, findings []JEGFinding) {
	seen := map[string]bool{}
	seenFold := map[string]string{}

	for _, e := range entries {
		n := strings.ReplaceAll(e.Name, "\\", "/")
		lower := strings.ToLower(n)
		add := func(reason, detail string) {
			findings = append(findings, JEGFinding{Reason: reason, Entry: n, Detail: detail})
		}

		if strings.Contains(n, "..") {
			add(JEGReasonSlipPath, "dotdot")
		}
		if strings.HasPrefix(n, "/") || strings.HasPrefix(n, "\\") {
			add(JEGReasonAbsoluteEntry, "leading-slash")
		}
		// 盘符
		if len(n) >= 2 && n[1] == ':' {
			add(JEGReasonAbsoluteEntry, "drive")
		}

		if seen[n] {
			add(JEGReasonDuplicateEntry, "exact")
		}
		seen[n] = true
		if prior, ok := seenFold[lower]; ok && prior != n {
			add(JEGReasonCaseCollision, "fold:"+prior)
		}
		seenFold[lower] = n

		// 多发行版本覆盖
		if strings.HasPrefix(lower, "meta-inf/versions/") {
			if !policy.AllowMultiRelease {
				add(JEGReasonMultiRelease, "multi-release-jar")
			}
		}

		// 签名制品
		if policy.ForbidSignatureArtifacts && strings.HasPrefix(lower, "meta-inf/") {
			ext := jegExt(n)
			if ext == ".sf" || ext == ".rsa" || ext == ".dsa" || ext == ".ec" {
				add(JEGReasonSignatureArtifact, ext)
			}
		}

		// SPI 服务注册
		if strings.HasPrefix(lower, "meta-inf/services/") {
			if policy.ForbidServiceFiles {
				add(JEGReasonServiceInject, "forbidden")
			} else {
				add(JEGReasonServiceInject, "register")
			}
		}

		// 引导类包覆盖
		if strings.HasPrefix(lower, "java/") || strings.HasPrefix(lower, "javax/") ||
			strings.HasPrefix(lower, "sun/") || strings.HasPrefix(lower, "jdk/") {
			add(JEGReasonBootClassPath, "boot-package")
		}

		// 可执行/脚本成员
		if !e.IsDir {
			ext := jegExt(n)
			if ext != "" {
				execExt := map[string]bool{
					".exe": true, ".dll": true, ".so": true, ".dylib": true,
					".bat": true, ".cmd": true, ".sh": true, ".jnlp": true, ".ps1": true,
				}
				if execExt[ext] && !policy.AllowedExecutableExt[ext] {
					add(JEGReasonExecutableMember, ext)
				}
			}
		}
	}
	return len(findings) == 0, findings
}
