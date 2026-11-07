package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	swnMaxFindings     = 32
	swnMaxProps        = 256 * 1024
	swnReasonMissing   = "missing"
	swnReasonSymlink   = "symlink"
	swnReasonTooLarge  = "too-large"
	swnReasonUnread    = "unreadable"
	swnReasonName      = "level-name-invalid"
	swnReasonDirLink   = "world-dir-symlink"
	swnReasonLevelType = "level-type-unknown"
	swnReasonGenerator = "generator-settings-present"
	swnReasonNoProps   = "properties-missing"
)

var swnKnownLevelTypes = map[string]bool{
	"default":              true,
	"flat":                 true,
	"large_biomes":         true,
	"amplified":            true,
	"single_biome_surface": true,
	"normal":               true,
	"customized":           true,
}

type WorldNameFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type WorldNameAudit struct {
	ServerDir string
	Findings  []WorldNameFinding
}

func (a *WorldNameAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= swnMaxFindings {
		return
	}
	a.Findings = append(a.Findings, WorldNameFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WorldNameAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *WorldNameAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *WorldNameAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "世界目录配置未发现风险"
	}
	sorted := make([]WorldNameFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].File != sorted[j].File {
			return sorted[i].File < sorted[j].File
		}
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Detail < sorted[j].Detail
	})
	var b strings.Builder
	for i, f := range sorted {
		if i >= 12 {
			b.WriteString(fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(f.File)
		b.WriteString(": ")
		b.WriteString(f.Reason)
		if f.Detail != "" {
			b.WriteString("(")
			b.WriteString(f.Detail)
			b.WriteString(")")
		}
	}
	return b.String()
}

func swnValidateLevelName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "level-name 为空"
	}
	if filepath.IsAbs(trimmed) || strings.HasPrefix(trimmed, "/") {
		return "level-name 使用绝对路径"
	}
	if strings.Contains(trimmed, "..") {
		return "level-name 包含越界片段"
	}
	if strings.ContainsAny(trimmed, "\\:") {
		return "level-name 包含反斜杠或盘符"
	}
	if cfgHasControlChars(trimmed) {
		return "level-name 含控制字符"
	}
	return ""
}

func AuditServerWorldName(serverDir string) *WorldNameAudit {
	a := &WorldNameAudit{ServerDir: serverDir}
	const rel = "server.properties"
	if serverDir == "" {
		a.add(".", swnReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", swnReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, swnReasonSymlink, "属性文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, swnMaxProps)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			a.add(rel, swnReasonNoProps, "未找到服务器属性文件", false)
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, swnReasonTooLarge, fmt.Sprintf("属性文件超过 %d 字节", swnMaxProps), true)
			return a
		}
		a.add(rel, swnReasonUnread, "属性文件不可读", false)
		return a
	}
	props := pxParseProperties(string(data))
	if len(props) == 0 {
		a.add(rel, swnReasonNoProps, "属性文件为空或格式不可识别", false)
		return a
	}

	levelName := "world"
	if raw, found := props["level-name"]; found {
		if detail := swnValidateLevelName(raw); detail != "" {
			a.add(rel, swnReasonName, detail, true)
		} else {
			levelName = strings.TrimSpace(raw)
		}
	}

	if levelName != "" && !strings.Contains(levelName, "..") {
		candidate := filepath.Join(serverDir, filepath.FromSlash(levelName))
		if info, err := os.Lstat(candidate); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				a.add(levelName, swnReasonDirLink, "世界目录为符号链接，数据可落在服务器目录之外", true)
			}
		}
	}

	if raw, found := props["level-type"]; found {
		normalized := strings.ToLower(strings.TrimSpace(raw))
		if normalized != "" && !swnKnownLevelTypes[normalized] && !strings.HasPrefix(normalized, "minecraft:") {
			a.add(rel, swnReasonLevelType, "level-type 使用了未知生成器", false)
		}
	}

	if raw, found := props["generator-settings"]; found {
		trimmed := strings.TrimSpace(raw)
		if trimmed != "" && trimmed != "{}" {
			a.add(rel, swnReasonGenerator, "generator-settings 含自定义生成参数", false)
		}
	}

	return a
}
