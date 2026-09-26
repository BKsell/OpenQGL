package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// 本文件集中放置跨模块复用的输入/路径校验工具。
// 之前 user.go / modpack.go / loader.go 各自手写一遍"在不在某个根目录下"，
// 逻辑重复且容易漏 case，抽出来后所有 renderer 传入的路径都过同一套检查。

// maxDownloadBytes 单次下载最大体积 2 GiB，防恶意 CDN / mod repo 塞多 G 文件。
const maxDownloadBytes = 2 << 30

// safeImageExts 允许作为背景图/头像/缩略图的扩展名。
var safeImageExts = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".bmp":  true,
	".webp": true,
}

// safeArchiveExts 允许用户导入的压缩包类型（modpack / resourcepack）。
var safeArchiveExts = map[string]bool{
	".zip": true,
	".mrpack": true, // Modrinth modpack
}

// IsSafeImageExt 判断扩展名是否是受支持的图片类型。
func IsSafeImageExt(path string) bool {
	return safeImageExts[strings.ToLower(filepath.Ext(path))]
}

// IsSafeArchiveExt 判断扩展名是否是受支持的压缩包类型。
func IsSafeArchiveExt(path string) bool {
	return safeArchiveExts[strings.ToLower(filepath.Ext(path))]
}

// PathWithin 返回 clean 后的路径，并校验它没有跳出 root。
// 返回 ("", false) 表示路径穿越 / 不存在 / 是符号链接指向外面。
//
// 用法：
//
//	rel, ok := PathWithin("/opt/mc/versions", userSuppliedPath)
//
// 调用方拿到 rel 后再 Join(root, rel) 拼最终绝对路径，绝不直接用 userSuppliedPath。
func PathWithin(root string, p string) (string, bool) {
	if p == "" {
		return "", false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(rootAbs, abs)
	if err != nil {
		return "", false
	}
	if rel == "." {
		return ".", true
	}
	if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", false
	}
	return rel, true
}

// IsSymlink 报告给定路径是否是符号链接本身（不跟随）。
func IsSymlink(p string) bool {
	info, err := os.Lstat(p)
	if err != nil {
		return false
	}
	return info.Mode()&fs.ModeSymlink != 0
}

// SafeJoin 在 root 下拼一个相对子路径，任何一步越界都返回 false。
// 用于 renderer 传 "versions/1.20/mods" 这种相对路径时，确保它真的在 root 里。
func SafeJoin(root string, rel string) (string, bool) {
	clean := filepath.Clean("/" + rel) // 先做成绝对路径再 Clean，吞掉 ../
	clean = strings.TrimPrefix(clean, "/")
	if clean == "." || clean == "" {
		return "", false
	}
	full := filepath.Join(root, clean)
	if _, ok := PathWithin(root, full); !ok {
		return "", false
	}
	return full, true
}

// SanitizeFilename 把用户输入的文件名里危险字符替换掉，避免路径分隔符 / 保留名。
// 不做空判断（空串由调用方决定怎么处理）。
func SanitizeFilename(name string) string {
	if name == "" {
		return name
	}
	// Windows 保留字符
	for _, c := range []string{`<`, `>`, `:`, `"`, `/`, `\`, `|`, `?`, `*`} {
		name = strings.ReplaceAll(name, c, "_")
	}
	// 去掉首尾空格和点（Windows 不允许文件名以点结尾）
	name = strings.TrimLeft(name, " .")
	name = strings.TrimRight(name, " .")
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

// ValidateModName 校验 mod / 版本 ID 是否合法：
// 只允许字母数字、点、下划线、短横线，长度 1~64。
// 这是 Minecraft 版本目录、mod 文件名的实际约定。
func ValidateModName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// ValidateURL 只允许 http/https，且长度 <= 2048（Go url.Parse 不会替你挡超长串）。
func ValidateURL(raw string) bool {
	if raw == "" || len(raw) > 2048 {
		return false
	}
	lower := strings.ToLower(raw)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// MaxFileSize 返回文件大小是否在安全上限内。
// limitBytes <= 0 时用默认 2 GiB。
func MaxFileSize(p string, limitBytes int64) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	if limitBytes <= 0 {
		limitBytes = maxDownloadBytes
	}
	return info.Size() >= 0 && info.Size() <= limitBytes
}
