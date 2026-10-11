package main

// patchguard：补丁清单守卫。
//
// 场景：实例/启动器升级会拉取 patch.json（文件清单：action + 相对路径 +
// 哈希 + 大小）。伪造补丁清单可让启动器把"add"动作的目标写到任意相对路径
// （覆盖 jar / 配置 / 脚本），或声明超大量级拖垮升级。本模块：
//   - 每条补丁：action 仅允许 add / replace / remove；
//   - file 相对路径：无穿越 / 盘符 / 反斜杠 / 控制字符，长度有界；
//   - hash：40 位 sha1 或 64 位 sha256 或空；size 非负且单条有界；
//   - 总条数与总字节有界；
//   - 同文件重复操作检测（后操作覆盖前操作属于高风险模式，直接拒绝）。

import (
	"encoding/json"
	"strings"
)

// PatchLimits 补丁清单守卫的量化边界。
type PatchLimits struct {
	MaxEntries   int
	MaxFileLen   int
	MaxEntrySize int64
	MaxTotalSize int64
}

func defaultPatchLimits() PatchLimits {
	return PatchLimits{MaxEntries: 100000, MaxFileLen: 512, MaxEntrySize: 1 << 31, MaxTotalSize: 8 << 30}
}

type patchItem struct {
	Action string `json:"action"`
	File   string `json:"file"`
	Hash   string `json:"hash"`
	Size   int64  `json:"size"`
}

type patchVerdict struct {
	OK     bool
	Reason string
	Total  int
	Bytes  int64
}

// validatePatchItem 校验单条补丁。
func validatePatchItem(it patchItem, lim PatchLimits) string {
	switch it.Action {
	case "add", "replace", "remove":
	default:
		return "action:" + it.Action
	}
	f := it.File
	if f == "" {
		return "file-empty"
	}
	if len(f) > lim.MaxFileLen {
		return "file-too-long"
	}
	if strings.HasPrefix(f, "/") || (len(f) > 1 && f[1] == ':') {
		return "file-absolute"
	}
	if hasControlCharStr(f) {
		return "file-control-char"
	}
	if strings.Contains(f, "\\") {
		return "file-backslash"
	}
	if strings.Contains(f, "..") {
		return "file-dotdot"
	}
	if it.Size < 0 {
		return "size-negative"
	}
	if it.Size > lim.MaxEntrySize {
		return "size-overflow"
	}
	if it.Hash != "" {
		if r := validateQueueHash(it.Hash); r != "" {
			return "hash:" + r
		}
	}
	return ""
}

// ValidatePatchManifest 校验补丁清单。
func ValidatePatchManifest(raw []byte, lim PatchLimits) patchVerdict {
	if lim.MaxEntries == 0 {
		lim = defaultPatchLimits()
	}
	vd := patchVerdict{OK: true}
	if len(raw) > 32<<20 {
		vd.OK = false
		vd.Reason = "manifest-too-large"
		return vd
	}
	var items []patchItem
	if err := json.NewDecoder(strings.NewReader(string(raw))).Decode(&items); err != nil {
		vd.OK = false
		vd.Reason = "parse-fail"
		return vd
	}
	if len(items) > lim.MaxEntries {
		vd.OK = false
		vd.Reason = "entries-overflow"
		return vd
	}
	seen := make(map[string]string, len(items))
	for i, it := range items {
		if r := validatePatchItem(it, lim); r != "" {
			vd.OK = false
			vd.Reason = "item:" + itoaSafe(i) + ":" + r
			return vd
		}
		if prev, dup := seen[it.File]; dup {
			vd.OK = false
			vd.Reason = "dup:" + it.File + ":" + prev
			return vd
		}
		seen[it.File] = it.Action
		vd.Bytes += it.Size
		if vd.Bytes > lim.MaxTotalSize {
			vd.OK = false
			vd.Reason = "total-overflow"
			return vd
		}
	}
	vd.Total = len(items)
	return vd
}

// SummarizePatchVerdict 压成一行。
func SummarizePatchVerdict(vd patchVerdict) string {
	if vd.OK {
		return "patch ok entries=" + itoaSafe(vd.Total) + " bytes=" + itoaSafe64(vd.Bytes)
	}
	return "patch bad " + vd.Reason
}
