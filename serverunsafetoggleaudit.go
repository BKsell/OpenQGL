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
	sunMaxFindings      = 36
	sunMaxProps         = 256 * 1024
	sunMaxYAML          = 512 * 1024
	sunReasonOK         = "ok"
	sunReasonMissing    = "missing"
	sunReasonSymlink    = "symlink"
	sunReasonTooLarge   = "too-large"
	sunReasonUnreadable = "unreadable"
	sunReasonBadValue   = "bad-value"
	sunReasonSecureOff  = "secure-profile-off"
	sunReasonUsername   = "username-validation-off"
	sunReasonPermGen    = "perm-gen-allowed"
	sunReasonToggle     = "unsupported-toggle-enabled"
)

type UnsafeToggleFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type UnsafeToggleAudit struct {
	ServerDir string
	Findings  []UnsafeToggleFinding
}

func (a *UnsafeToggleAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= sunMaxFindings {
		return
	}
	a.Findings = append(a.Findings, UnsafeToggleFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *UnsafeToggleAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *UnsafeToggleAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *UnsafeToggleAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "实验性开关未发现风险"
	}
	sorted := make([]UnsafeToggleFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].File != sorted[j].File {
			return sorted[i].File < sorted[j].File
		}
		return sorted[i].Reason < sorted[j].Reason
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

func sunLoadText(a *UnsafeToggleAudit, root, rel string, maxBytes int64) (string, bool) {
	path := filepath.Join(root, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, sunReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return "", false
	}
	data, err := readBoundedFile(path, maxBytes)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return "", false
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, sunReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", maxBytes), true)
			return "", false
		}
		a.add(rel, sunReasonUnreadable, "配置文件不可读", false)
		return "", false
	}
	return string(data), true
}

func sunBool(flat map[string]string, path string) (bool, bool) {
	value, ok := cfgLookup(flat, path)
	if !ok {
		return false, false
	}
	switch strings.ToLower(cfgStripQuotes(value)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	default:
		return false, false
	}
}

func sunToggleDetail(key string) string {
	trimmed := strings.TrimPrefix(key, "unsupported-settings.")
	return "已启用实验性开关 " + trimmed
}

func AuditServerUnsafeToggles(serverDir string) *UnsafeToggleAudit {
	a := &UnsafeToggleAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", sunReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sunReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", sunReasonMissing, "服务器目录不存在", false)
		return a
	}

	if text, ok := sunLoadText(a, serverDir, "server.properties", sunMaxProps); ok {
		props := pxParseProperties(text)
		if value, found := props["enforce-secure-profile"]; found {
			if strings.EqualFold(strings.TrimSpace(value), "false") {
				a.add("server.properties", sunReasonSecureOff, "enforce-secure-profile=false 允许未签名聊天", false)
			}
		}
		if value, found := props["network-compression-threshold"]; found {
			if number, parsed := cfgParseInt(strings.TrimSpace(value)); !parsed {
				a.add("server.properties", sunReasonBadValue, "network-compression-threshold 非整数", true)
			} else if number > 0 && number < 64 {
				a.add("server.properties", sunReasonBadValue, "network-compression-threshold 过小", false)
			}
		}
	}

	text, ok := sunLoadText(a, serverDir, "config/paper-global.yml", sunMaxYAML)
	if !ok {
		return a
	}
	flat := cfgFlattenYAML(text)

	if value, found := sunBool(flat, "unsupported-settings.perform-username-validation"); found && !value {
		a.add("config/paper-global.yml", sunReasonUsername, "关闭用户名校验，可伪造玩家名", true)
	}
	if value, found := sunBool(flat, "unsupported-settings.allow-perm-gen"); found && value {
		a.add("config/paper-global.yml", sunReasonPermGen, "允许权限生成器写入配置", true)
	}

	reported := map[string]bool{
		"unsupported-settings.perform-username-validation": true,
		"unsupported-settings.allow-perm-gen":              true,
	}
	for key := range flat {
		if !strings.HasPrefix(key, "unsupported-settings.") {
			continue
		}
		if reported[key] {
			continue
		}
		enabled, parsed := sunBool(flat, key)
		if !parsed || !enabled {
			continue
		}
		a.add("config/paper-global.yml", sunReasonToggle, sunToggleDetail(key), true)
	}

	if raw, found := cfgLookup(flat, "watchdog.early-warning-every"); found {
		switch strings.ToLower(cfgStripQuotes(raw)) {
		case "true", "false":
			a.add("config/paper-global.yml", sunReasonBadValue, "watchdog.early-warning-every 为布尔值", true)
		}
	}
	return a
}
