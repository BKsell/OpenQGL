package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// launchprofileguard.go —— launcher_profiles.json 只读加固内核。
//
// launcher_profiles.json 是官方启动器（及第三方启动器）的状态文件，记录每个
// profile 的名称、游戏目录、Java 目录、最近版本等。它可能来自用户手动编辑、
// 整合包预置或旧启动器迁移——内容不可信。
//
// 历史风险：
//   - 文件体积无限大 / profile 条目无限多 → 解析时内存与 CPU 耗尽；
//   - gameDir / javaDir 指向系统关键目录（Windows 系统目录、Unix 根目录、
//     /etc、/usr 等）→ 启动器会把日志、options.txt、崩溃报告写进系统目录；
//   - 名称 / 版本 ID 夹带控制字符或超长 → 拼进路径 / 展示层时注入；
//   - JSON 字段类型与预期不符 → 下游 panic。
//
// 本内核做纯读校验：给出裁决与清洗后的安全视图，不负责落盘。

// LaunchProfileLimits 是 profiles 文件解析的规模上限。
type LaunchProfileLimits struct {
	MaxBytes     int
	MaxProfiles  int
	NameRunes    int
	PathRunes    int
	VersionRunes int
}

func defaultLaunchProfileLimits() LaunchProfileLimits {
	return LaunchProfileLimits{
		MaxBytes:     1 << 20, // 1 MiB
		MaxProfiles:  500,
		NameRunes:    64,
		PathRunes:    4096,
		VersionRunes: 64,
	}
}

// ProfileFinding 是 profiles 文件里的一处问题。
type ProfileFinding struct {
	Severity string // "error"（不可用）| "warn"（提示）
	Path     string // JSON 定位路径，如 $.profiles.<name>.gameDir
	Reason   string
}

// LaunchProfileVerdict 是一次 profiles 校验的结果。
type LaunchProfileVerdict struct {
	OK        bool
	Findings  []ProfileFinding
	ProfileID string
	Name      string
	GameDir   string
	JavaDir   string
	VersionID string
	Type      string
}

// dangerousProfileDirs 返回跨平台的危险目标目录集合。判断依据：把清洗后的
// 绝对路径与这些前缀比对，命中即视为越界。
func dangerousProfileDirs() []string {
	base := []string{
		"/etc", "/usr", "/bin", "/sbin", "/lib", "/boot", "/proc", "/sys", "/dev",
		"/var", "/opt", "/root",
	}
	if runtime.GOOS == "windows" {
		// 常见盘符根目录与系统目录。对 UNC 路径（\\server\share）一律拒绝。
		for _, p := range []string{"c:\\", "d:\\", "e:\\", "C:\\", "D:\\", "E:\\"} {
			base = append(base, p)
		}
		base = append(base,
			"C:\\Windows", "C:\\Windows\\System32", "C:\\Windows\\SysWOW64",
			"C:\\Program Files", "C:\\Program Files (x86)", "C:\\ProgramData",
			"C:\\Users", "C:\\Users\\Public",
			"Windows", "Windows\\System32",
		)
	}
	return base
}

// sanitizeProfilePath 对用户可控的路径字段做安全归一：拒绝控制字符与超长、
// 拒绝 UNC / 相对路径（游戏目录必须是绝对路径）、拒绝危险目录前缀。
// 返回清洗后的绝对路径（未落盘验证存在性）与是否合法。
func sanitizeProfilePath(raw string, l LaunchProfileLimits) (string, *ProfileFinding) {
	if raw == "" {
		return "", &ProfileFinding{"error", "$", "路径为空"}
	}
	if len([]rune(raw)) > l.PathRunes {
		return "", &ProfileFinding{"error", "$", fmt.Sprintf("路径超过 %d 字符上限", l.PathRunes)}
	}
	if strings.ContainsAny(raw, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f") {
		return "", &ProfileFinding{"error", "$", "路径含控制字符"}
	}
	if strings.HasPrefix(raw, `\\`) {
		return "", &ProfileFinding{"error", "$", "拒绝 UNC 网络路径"}
	}
	abs, err := filepath.Abs(filepath.Clean(raw))
	if err != nil {
		return "", &ProfileFinding{"error", "$", "路径无法归一化"}
	}
	// 相对路径经 Abs 后会落到 CWD 下——启动器 CWD 通常就在游戏根附近，仍可能
	// 指向意外位置；直接拒绝非绝对输入。
	if !filepath.IsAbs(raw) {
		return "", &ProfileFinding{"error", "$", "游戏目录必须是绝对路径"}
	}
	lower := strings.ToLower(abs)
	for _, d := range dangerousProfileDirs() {
		dl := strings.ToLower(filepath.Clean(d))
		if lower == dl || strings.HasPrefix(lower, strings.TrimSuffix(dl, string(filepath.Separator))+string(filepath.Separator)) {
			return "", &ProfileFinding{"error", "$", fmt.Sprintf("路径指向危险目录：%s", filepath.Clean(d))}
		}
	}
	return abs, nil
}

// sanitizeProfileName 校验 profile 名称：去首尾空白、拒绝控制字符、限长。
func sanitizeProfileName(raw string, l LaunchProfileLimits) (string, *ProfileFinding) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", &ProfileFinding{"error", "name", "profile 名称为空"}
	}
	if len([]rune(name)) > l.NameRunes {
		return "", &ProfileFinding{"error", "name", fmt.Sprintf("名称超过 %d 字符上限", l.NameRunes)}
	}
	if strings.ContainsAny(name, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f") {
		return "", &ProfileFinding{"error", "name", "名称含控制字符"}
	}
	return name, nil
}

// sanitizeVersionID 复用 configguard 的路径组件规则：版本 ID 会被拼进
// versions/<id>/ 路径，必须是单段安全名。
func sanitizeVersionID(raw string, l LaunchProfileLimits) (string, *ProfileFinding) {
	id := strings.TrimSpace(raw)
	if id == "" {
		return "", &ProfileFinding{"warn", "lastVersionId", "版本 ID 为空（profile 未选定版本）"}
	}
	if len([]rune(id)) > l.VersionRunes {
		return "", &ProfileFinding{"error", "lastVersionId", fmt.Sprintf("版本 ID 超过 %d 字符上限", l.VersionRunes)}
	}
	if err := sanitizePathComponent(id); err != nil {
		return "", &ProfileFinding{"error", "lastVersionId", err.Error()}
	}
	return id, nil
}

// auditLaunchProfiles 解析并校验 launcher_profiles.json 内容。
// 只读不落盘；返回主 profile（第一个解析成功且字段合法的条目）的安全视图。
func auditLaunchProfiles(data []byte, l LaunchProfileLimits) LaunchProfileVerdict {
	v := LaunchProfileVerdict{}
	if len(data) > l.MaxBytes {
		v.Findings = append(v.Findings, ProfileFinding{
			"error", "$", fmt.Sprintf("launcher_profiles.json 超过 %d 字节上限", l.MaxBytes),
		})
		return v
	}
	var doc struct {
		Profiles map[string]json.RawMessage `json:"profiles"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		v.Findings = append(v.Findings, ProfileFinding{"error", "$", "不是合法 JSON"})
		return v
	}
	if len(doc.Profiles) > l.MaxProfiles {
		v.Findings = append(v.Findings, ProfileFinding{
			"error", "$", fmt.Sprintf("profile 条目数 %d 超过 %d 上限", len(doc.Profiles), l.MaxProfiles),
		})
		return v
	}
	// 保证确定性：按 ID 排序处理，首个合法 profile 作为主 profile。
	ids := make([]string, 0, len(doc.Profiles))
	for id := range doc.Profiles {
		ids = append(ids, id)
	}
	sortStrings(ids)

	for _, id := range ids {
		raw := doc.Profiles[id]
		var p struct {
			Name      string `json:"name"`
			GameDir   string `json:"gameDir"`
			JavaDir   string `json:"javaDir"`
			LastVerID string `json:"lastVersionId"`
			Type      string `json:"type"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			v.Findings = append(v.Findings, ProfileFinding{
				"warn", "$.profiles." + id, "profile 字段类型不符，已跳过",
			})
			continue
		}
		// 字段级校验：名称 / 路径 / 版本 ID。
		name, f := sanitizeProfileName(p.Name, l)
		if f != nil {
			f.Path = "$.profiles." + id + "." + f.Path
			v.Findings = append(v.Findings, *f)
			continue
		}
		gameDir, f := sanitizeProfilePath(p.GameDir, l)
		if f != nil {
			f.Path = "$.profiles." + id + ".gameDir"
			v.Findings = append(v.Findings, *f)
			continue
		}
		javaDir := ""
		if p.JavaDir != "" {
			jd, f2 := sanitizeProfilePath(p.JavaDir, l)
			if f2 != nil {
				f2.Path = "$.profiles." + id + ".javaDir"
				v.Findings = append(v.Findings, *f2)
				continue
			}
			javaDir = jd
		}
		versionID, f := sanitizeVersionID(p.LastVerID, l)
		if f != nil && f.Severity == "error" {
			f.Path = "$.profiles." + id + ".lastVersionId"
			v.Findings = append(v.Findings, *f)
			continue
		}
		v.ProfileID = id
		v.Name = name
		v.GameDir = gameDir
		v.JavaDir = javaDir
		v.VersionID = versionID
		v.Type = p.Type
		if len(v.Findings) == 0 {
			v.OK = true
		} else {
			for _, it := range v.Findings {
				if it.Severity == "error" {
					v.OK = false
				}
			}
		}
		return v
	}
	if v.ProfileID == "" {
		v.Findings = append(v.Findings, ProfileFinding{
			"error", "$", "没有可用的 profile 条目",
		})
	}
	return v
}

// profileVerdictSummary 生成一句话结论。
func profileVerdictSummary(v LaunchProfileVerdict) string {
	if v.OK {
		return fmt.Sprintf("launcher_profiles.json 可用：profile %q，游戏目录 %s，版本 %q",
			v.Name, v.GameDir, v.VersionID)
	}
	return fmt.Sprintf("launcher_profiles.json 存在 %d 个问题，拒绝使用", len(v.Findings))
}
