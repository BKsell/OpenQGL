package main

// bindingguard.go —— Wails 前端绑定方法（renderer→Go）攻击面守卫。
//
// 背景：
//   Wails 会把 Go 上导出的绑定方法暴露给前端 JS。这些方法等价于"任意网页脚本都能调用的本地
//   RPC"：一旦前端页面存在 XSS、加载了远程内容、或被注入恶意脚本，攻击者就能借绑定方法用本地
//   权限读写文件、联网、甚至拼命令启动进程。因此对每个暴露面要回答：
//     - 是否接收路径/URL/命令/原始字节等危险输入；
//     - 是否真正落盘、删除、执行、改配置，或回传敏感数据（token/文件内容）；
//     - 危险输入是否经过对应校验（pathguard/SSRF/命令白名单）与必要的用户确认；
//     - 是否暴露了不该给前端的通用原语（RunCommand/ReadAnyFile/WriteAnyFile/Eval）。
//   本模块对一份"绑定方法元数据登记表"做策略审计，纯布尔/字符串判定，不使用正则。它不替代代码
//   审查，而是把"暴露面必须配套护栏"固化成可测试的清单。

import "strings"

const (
	BNDReasonPathNotValidated      = "binding-path-input-without-validation"
	BNDReasonURLNotValidated       = "binding-url-input-without-ssrf-validation"
	BNDReasonCommandNotWhitelisted = "binding-command-exec-without-allowlist"
	BNDReasonWriteNoConfirm        = "binding-write-or-delete-without-confirm"
	BNDReasonExecNoConfirm         = "binding-process-exec-without-confirm"
	BNDReasonReturnsSensitive      = "binding-returns-sensitive-data-to-renderer"
	BNDReasonGenericPrimitive      = "binding-dangerous-generic-primitive-exposed"
	BNDReasonRawBodyUnbounded      = "binding-raw-body-without-size-limit"
	BNDReasonNoOriginBoundary      = "binding-sensitive-method-without-origin-boundary"
)

// BNDCapability 描述绑定方法的能力位。
type BNDCapability struct {
	TakesPath        bool
	TakesURL         bool
	TakesCommandArgs bool
	TakesRawBody     bool
	WritesOrDeletes  bool
	ExecProcess      bool
	ReturnsSensitive bool
	GenericPrimitive bool // RunCommand/ReadFile/WriteFile/Eval/FetchAny 一类通用原语
}

// BNDGuard 描述该方法已配套的护栏。
type BNDGuard struct {
	PathValidated    bool
	URLValidated     bool
	CommandAllowlist bool
	WriteConfirmed   bool
	ExecConfirmed    bool
	RawBodyLimited   bool
	OriginEnforced   bool // 是否限制只接受可信前端源调用
}

// BNDBinding 是一个暴露给前端的方法登记项。
type BNDBinding struct {
	Name       string
	Capability BNDCapability
	Guard      BNDGuard
}

// BNDPolicy 设定暴露面最低护栏要求。
type BNDPolicy struct {
	RequireOriginBoundaryForSensitive bool
	RequireConfirmForExec             bool
	RequireConfirmForWrite            bool
	ForbidGenericPrimitives           bool
}

// BNDFinding 记录一处绑定面风险。
type BNDFinding struct {
	Reason string
	Method string
	Detail string
}

// DefaultBNDPolicy 默认对敏感方法要求来源边界、写/执行确认、禁用通用原语。
func DefaultBNDPolicy() BNDPolicy {
	return BNDPolicy{
		RequireOriginBoundaryForSensitive: true,
		RequireConfirmForExec:             true,
		RequireConfirmForWrite:            true,
		ForbidGenericPrimitives:           true,
	}
}

// bndGenericPrimitiveNames 是不应直接暴露给前端的通用原语名（小写包含匹配）。
var bndGenericPrimitiveNames = []string{
	"runcommand", "exec", "execcommand", "spawn",
	"readanyfile", "writeanyfile", "deleteanyfile",
	"readfile", "writefile", "eval", "fetchany", "openpath",
}

// BNDAudit 审计全部绑定方法。
func BNDAudit(bindings []BNDBinding, policy BNDPolicy) (safe bool, findings []BNDFinding) {
	for _, b := range bindings {
		c := b.Capability
		g := b.Guard
		name := strings.ToLower(b.Name)
		add := func(reason, detail string) {
			findings = append(findings, BNDFinding{Reason: reason, Method: b.Name, Detail: detail})
		}

		genericName := false
		for _, gn := range bndGenericPrimitiveNames {
			if name == gn {
				genericName = true
				break
			}
		}
		if c.GenericPrimitive || (genericName && (c.ExecProcess || c.WritesOrDeletes)) {
			if policy.ForbidGenericPrimitives {
				add(BNDReasonGenericPrimitive, "generic-primitive")
			}
		}

		if c.TakesPath && !g.PathValidated {
			add(BNDReasonPathNotValidated, "path")
		}
		if c.TakesURL && !g.URLValidated {
			add(BNDReasonURLNotValidated, "url")
		}
		if c.TakesCommandArgs && c.ExecProcess && !g.CommandAllowlist {
			add(BNDReasonCommandNotWhitelisted, "command")
		}
		if c.WritesOrDeletes && !g.WriteConfirmed && policy.RequireConfirmForWrite {
			add(BNDReasonWriteNoConfirm, "write/delete")
		}
		if c.ExecProcess && !g.ExecConfirmed && policy.RequireConfirmForExec {
			add(BNDReasonExecNoConfirm, "exec")
		}
		if c.TakesRawBody && !g.RawBodyLimited {
			add(BNDReasonRawBodyUnbounded, "body")
		}
		if c.ReturnsSensitive {
			add(BNDReasonReturnsSensitive, "token/file")
			if policy.RequireOriginBoundaryForSensitive && !g.OriginEnforced {
				add(BNDReasonNoOriginBoundary, "origin")
			}
		}
		// 任意危险能力都应有来源边界
		if (c.ExecProcess || c.WritesOrDeletes || c.TakesCommandArgs) &&
			policy.RequireOriginBoundaryForSensitive && !g.OriginEnforced {
			add(BNDReasonNoOriginBoundary, "privileged")
		}
	}
	return len(findings) == 0, findings
}
