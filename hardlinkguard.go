package main

// hardlinkguard.go —— 硬链接逃逸目录边界检测。
//
// 背景：
//   Zip Slip（jarentryguard）与符号链接（toctou/worldpath）之外，硬链接是另一条把数据带出受信
//   目录的通道：攻击者在实例目录里创建一个指向目录外敏感文件（如 tokenstore、其它实例存档）的
//   硬链接。硬链接与普通文件在路径上完全无法区分（不是 symlink，lstat 也是普通文件），只能靠
//   "同一卷上不同路径是否指向同一个 inode/文件 ID" 来识别。典型危害：
//     - 备份/打包实例时把硬链接目标（目录外凭据）一起带走上传；
//     - 删除实例时误删目录外共享文件（硬链接本身只是多一个名字，风险在读写内容外泄）；
//     - 解压时落地硬链接条目（zip 支持 hardlink 条目 type），后续写入穿透到外部。
//   本模块只做判定逻辑（输入由调用方用 os.SameFile / GetFileInformationByHandle 采集后喂入），
//   不直接触碰文件系统，便于在各平台统一测试；不使用正则。

const (
	HLReasonCrossDevice      = "hardlink-entry-cross-device"
	HLReasonEscapesBase      = "hardlink-target-escapes-base-directory"
	HLReasonZipHardlinkEntry = "archive-contains-hardlink-entry"
	HLReasonDuplicateInode   = "multiple-paths-same-inode-inside-and-outside-base"
	HLReasonEmptyPath        = "hardlink-path-empty"
)

// HLFileIdentity 是调用方采集到的一条路径的身份信息。
type HLFileIdentity struct {
	Path       string
	Device     uint64
	FileID     uint64
	IsHardlink bool // 归档条目自报 hardlink，或平台 API 报告链接数 >1
	InsideBase bool
}

// HLFinding 记录一处硬链接风险。
type HLFinding struct {
	Reason string
	Path   string
	Target string
}

// HLPolicy 配置硬链接审计策略。
type HLPolicy struct {
	RejectArchiveHardlinks bool // 解压场景：直接拒绝 hardlink 类型归档条目
	RequireSameDevice      bool // 落盘目标必须与基目录在同一卷
}

// DefaultHLPolicy 默认拒绝归档 hardlink、要求同卷。
func DefaultHLPolicy() HLPolicy {
	return HLPolicy{RejectArchiveHardlinks: true, RequireSameDevice: true}
}

// HLAuditResult 汇总审计结果。
type HLAuditResult struct {
	Safe     bool
	Findings []HLFinding
}

// HLBaseDevice 存放基目录所在卷，用于跨卷判定。
type HLBaseDevice struct {
	Device uint64
}

// HLAuditEntries 审计一组文件身份。baseDevice 为基目录卷（0 表示未知，跳过跨卷判定）。
func HLAuditEntries(policy HLPolicy, baseDevice uint64, entries []HLFileIdentity) HLAuditResult {
	var findings []HLFinding
	// inode -> 是否曾在基目录外出现
	outsideByID := map[string]bool{}
	// inode -> 基目录内代表路径
	insidePathByID := map[string]string{}

	for _, e := range entries {
		if e.Path == "" {
			findings = append(findings, HLFinding{Reason: HLReasonEmptyPath})
			continue
		}
		key := hlKey(e.Device, e.FileID)

		if policy.RejectArchiveHardlinks && e.IsHardlink {
			findings = append(findings, HLFinding{
				Reason: HLReasonZipHardlinkEntry, Path: e.Path})
		}

		if policy.RequireSameDevice && baseDevice != 0 && e.Device != 0 &&
			e.Device != baseDevice {
			findings = append(findings, HLFinding{
				Reason: HLReasonCrossDevice, Path: e.Path})
		}

		if e.InsideBase {
			// 该 inode 已在目录外出现过，说明基目录内路径是指向外部的硬链接
			if outsideByID[key] {
				findings = append(findings, HLFinding{
					Reason: HLReasonEscapesBase, Path: e.Path,
					Target: insidePathByID[key]})
			}
			if _, ok := insidePathByID[key]; !ok {
				insidePathByID[key] = e.Path
			}
		} else {
			outsideByID[key] = true
			// 外部 inode 与基目录内某路径相同
			if in, ok := insidePathByID[key]; ok {
				findings = append(findings, HLFinding{
					Reason: HLReasonDuplicateInode, Path: in, Target: e.Path})
			}
		}
	}

	return HLAuditResult{Safe: len(findings) == 0, Findings: findings}
}

// HLHasReason 判定是否含某类问题。
func (r HLAuditResult) HasReason(reason string) bool {
	for _, f := range r.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func hlKey(device, fileID uint64) string {
	return itoaHL64(device) + ":" + itoaHL64(fileID)
}

func itoaHL64(i uint64) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
