package main

// tempfileguard.go —— 临时文件/目录创建的可预测性、权限与清理守卫。
//
// 背景：
//   启动器下载、解压、备份、写崩溃报告时会用到临时文件。不安全的临时文件用法会被本地其他用户/
//   进程利用：
//     - 名字可预测（固定名 launcher-tmp.zip / 用 pid+时间且可猜），在共享 TEMP 下被预先创建为
//       符号链接，导致解压/写入沿链接写到任意路径（symlink attack）；
//     - 用 0644/0777 创建，其它本地用户可读，凭据/账号数据落进临时目录；
//     - 写在固定公共目录却不做"独占创建（O_CREATE|O_EXCL）"，存在 TOCTOU 竞争（toctouguard 另管）；
//     - 用完不删除，或异常路径泄漏（defer 缺失、跨平台 rename 残留 .tmp）；
//     - TEMP 环境变量被指向奇怪位置（指向远程/可被他人写的目录）。
//   本模块审计一份"临时文件创建登记表"，给出合规结论，纯字符串/布尔判定，不使用正则。

import "strings"

const (
	TFGReasonPredictableName   = "tempfile-predictable-name"
	TFGReasonSharedDir         = "tempfile-in-shared-or-world-writable-dir"
	TFGReasonOverlyPermissive  = "tempfile-created-world-or-group-accessible"
	TFGReasonNoExclusiveCreate = "tempfile-created-without-exclusive-flag"
	TFGReasonNotCleanedUp      = "tempfile-not-scheduled-for-cleanup"
	TFGReasonSensitiveContent  = "tempfile-holds-sensitive-content"
	TFGReasonSuspiciousTempDir = "tempfile-temp-dir-env-suspicious"
	TFGReasonRemoteTemp        = "tempfile-temp-dir-on-remote-or-unc"
)

// TFGView 描述一次临时文件/目录的创建方式。
type TFGView struct {
	NamePattern           string // 形如 "dl-*.tmp"，需含随机占位
	Dir                   string
	SharedOrWorldWritable bool
	ModePerm              uint32 // 创建权限位
	ExclusiveCreate       bool   // O_CREATE|O_EXCL 语义
	CleanupScheduled      bool
	HoldsSensitive        bool
	TempDirUNC            bool
}

// TFGFinding 记录一处临时文件风险。
type TFGFinding struct {
	Reason string
	Detail string
}

// TFGPolicy 设定临时文件策略。
type TFGPolicy struct {
	MaxPermForSensitive uint32 // 敏感临时文件最高允许权限（一般 0600）
	MaxPermNormal       uint32
}

// DefaultTFGPolicy 敏感 0600、普通 0640。
func DefaultTFGPolicy() TFGPolicy {
	return TFGPolicy{MaxPermForSensitive: 0600, MaxPermNormal: 0640}
}

// tfgHasRandomPlaceholder 粗判命名模板是否包含随机占位。
func tfgHasRandomPlaceholder(pattern string) bool {
	p := strings.ToLower(pattern)
	for _, marker := range []string{"*", "?", "random", "rand", "tmpfile", "xxxx"} {
		if strings.Contains(p, marker) {
			// "*" 单独出现可能只是扩展名通配，要求模板里有明显随机段
			if marker == "*" {
				// 接受形如 prefix-*.tmp / *.tmp-* 的随机名模板
				if strings.Contains(p, "*.tmp") || strings.Contains(p, "-*") ||
					strings.Contains(p, "*_") {
					return true
				}
				continue
			}
			return true
		}
	}
	return false
}

// TFGEvaluate 审计一次临时文件创建。
func TFGEvaluate(v TFGView, policy TFGPolicy) (safe bool, findings []TFGFinding) {
	if v.TempDirUNC {
		findings = append(findings, TFGFinding{Reason: TFGReasonRemoteTemp})
	}
	if !tfgHasRandomPlaceholder(v.NamePattern) {
		findings = append(findings, TFGFinding{Reason: TFGReasonPredictableName,
			Detail: v.NamePattern})
	}
	if v.SharedOrWorldWritable {
		findings = append(findings, TFGFinding{Reason: TFGReasonSharedDir, Detail: v.Dir})
	}
	maxPerm := policy.MaxPermNormal
	if v.HoldsSensitive {
		maxPerm = policy.MaxPermForSensitive
	}
	// 其它位/组位超出上限即判过宽
	if v.ModePerm&^uint32(0777) != 0 {
		// 高位（如 setuid）天然不合规
		findings = append(findings, TFGFinding{Reason: TFGReasonOverlyPermissive,
			Detail: tfgOctal(v.ModePerm)})
	} else if v.ModePerm&^maxPerm != 0 {
		findings = append(findings, TFGFinding{Reason: TFGReasonOverlyPermissive,
			Detail: tfgOctal(v.ModePerm)})
	}
	if !v.ExclusiveCreate {
		findings = append(findings, TFGFinding{Reason: TFGReasonNoExclusiveCreate})
	}
	if !v.CleanupScheduled {
		findings = append(findings, TFGFinding{Reason: TFGReasonNotCleanedUp})
	}
	if v.HoldsSensitive && (v.SharedOrWorldWritable || v.ModePerm&0077 != 0) {
		findings = append(findings, TFGFinding{Reason: TFGReasonSensitiveContent,
			Detail: tfgOctal(v.ModePerm)})
	}
	d := strings.ToLower(v.Dir)
	for _, bad := range []string{"\\temp\\public", "/tmp/shared", "c:\\windows\\temp\\allusers"} {
		if strings.Contains(d, bad) {
			findings = append(findings, TFGFinding{Reason: TFGReasonSuspiciousTempDir, Detail: d})
			break
		}
	}
	return len(findings) == 0, findings
}

func tfgOctal(m uint32) string {
	if m == 0 {
		return "0"
	}
	var b []byte
	for shift := 9; shift >= 0; shift -= 3 {
		b = append(b, byte('0'+(m>>uint(shift))&7))
	}
	// 去掉前导 0
	out := strings.TrimLeft(string(b), "0")
	if out == "" {
		out = "0"
	}
	return out
}
