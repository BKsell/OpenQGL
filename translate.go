package main

import (
	"bufio"
	"embed"
	"os"
	"strings"
	"sync"
	"unicode"
)

//go:embed resources/ModData.txt
var modDataFile embed.FS

// ModTranslationEntry 翻译条目
type ModTranslationEntry struct {
	English string `json:"english"`
	Chinese string `json:"chinese"`
}

// modTranslationCache 翻译缓存
var (
	translationEntries []ModTranslationEntry
	translationLoaded  bool
	translationMutex  sync.RWMutex
)

// loadTranslations 加载翻译对照表（只加载一次）
func loadTranslations() {
	translationMutex.Lock()
	defer translationMutex.Unlock()

	if translationLoaded {
		return
	}
	translationLoaded = true

	data, err := modDataFile.ReadFile("resources/ModData.txt")
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 每行用 ¨ 分隔多个映射条目
		parts := strings.Split(line, "¨")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			// 每个 | 分隔 英文标识|中文翻译
			idx := strings.Index(part, "|")
			if idx <= 0 || idx >= len(part)-1 {
				continue
			}
			english := strings.TrimSpace(part[:idx])
			chinese := strings.TrimSpace(part[idx+1:])
			if english != "" && chinese != "" {
				translationEntries = append(translationEntries, ModTranslationEntry{
					English: english,
					Chinese: chinese,
				})
			}
		}
	}
}

// TranslateModName 将英文 Mod 名称/Slug 翻译为中文
// 支持精确匹配和前缀匹配
func (a *App) TranslateModName(english string) string {
	loadTranslations()

	translationMutex.RLock()
	defer translationMutex.RUnlock()

	lowerEnglish := strings.ToLower(strings.TrimSpace(english))

	// 1. 精确匹配（去掉 @ 后缀比较）
	for _, entry := range translationEntries {
		key := strings.TrimSuffix(entry.English, "@")
		if strings.ToLower(key) == lowerEnglish {
			return entry.Chinese
		}
	}

	// 2. 前缀匹配（@ 开头的条目，如 "industrial-craft@" 匹配 "industrial-craft-2-2-8-110"）
	for _, entry := range translationEntries {
		if strings.HasSuffix(entry.English, "@") {
			prefix := strings.ToLower(entry.English[:len(entry.English)-1])
			if strings.HasPrefix(lowerEnglish, prefix) {
				return entry.Chinese
			}
		}
	}

	// 3. 包含匹配（不带 @ 的条目，检查英文是否包含 key）
	for _, entry := range translationEntries {
		if !strings.HasSuffix(entry.English, "@") {
			key := strings.ToLower(entry.English)
			if strings.Contains(lowerEnglish, key) && len(key) > 3 {
				return entry.Chinese
			}
		}
	}

	return english // 无匹配则返回原名
}

// SearchModsByChineseName 通过中文名称搜索 Mod（返回所有匹配的英文原名）
func (a *App) SearchModsByChineseName(chineseQuery string) []string {
	loadTranslations()

	translationMutex.RLock()
	defer translationMutex.RUnlock()

	query := strings.ToLower(strings.TrimSpace(chineseQuery))
	var results []string

	for _, entry := range translationEntries {
		chineseLower := strings.ToLower(entry.Chinese)
		if strings.Contains(chineseLower, query) {
			results = append(results, entry.English)
		}
	}

	return results
}

// GetTranslationCount 获取已加载的翻译条目数量
func (a *App) GetTranslationCount() int {
	loadTranslations()
	translationMutex.RLock()
	defer translationMutex.RUnlock()
	return len(translationEntries)
}

// fuzzyMatch 模糊匹配：检查两个字符串的相似度
func fuzzyMatch(s, t string) float64 {
	s = strings.ToLower(s)
	t = strings.ToLower(t)
	if s == t {
		return 1.0
	}
	// 计算 Levenshtein 距离的简化版本
	lenS := len(s)
	lenT := len(t)
	if lenS == 0 { return 0 }
	if lenT == 0 { return 0 }

	matrix := make([][]int, lenS+1)
	for i := range matrix {
		matrix[i] = make([]int, lenT+1)
		matrix[i][0] = i
	}
	for j := 0; j <= lenT; j++ {
		matrix[0][j] = j
	}
	for i := 1; i <= lenS; i++ {
		for j := 1; j <= lenT; j++ {
			cost := 1
			if s[i-1] == t[j-1] {
				cost = 0
			}
			matrix[i][j] = min3(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}
	maxLen := lenS
	if lenT > maxLen { maxLen = lenT }
	return 1.0 - float64(matrix[lenS][lenT])/float64(maxLen)
}

func min3(a, b, c int) int {
	if a < b { if a < c { return a } else { return c } }
	if b < c { return b }
	return c
}

// isChinese 判断字符串是否包含中文
func isChinese(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// GetModTranslationFileContent 获取翻译文件内容（用于显示开源协议信息）
func (a *App) GetModTranslationFileContent() (string, error) {
	data, err := modDataFile.ReadFile("resources/ModData.txt")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ReadLicenseFile 读取 Apache License 文件内容
func (a *App) ReadLicenseFile() string {
	data, err := os.ReadFile("resources/APACHE_LICENSE.txt")
	if err != nil {
		return ""
	}
	return string(data)
}
