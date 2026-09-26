package main

import (
	"bufio"
	"embed"
	"sort"
	"strings"
	"sync"
	"unicode"
)

//go:embed resources/ModData.txt
var modDataFile embed.FS

type ModTranslationEntry struct {
	English string `json:"english"`
	Chinese string `json:"chinese"`
}

// prefixRule 是前缀匹配的一条规则，loadTranslations 时按前缀长度降序排好，
// 这样多前缀同时命中时永远命中最长的那个，结果确定可复现。
type prefixRule struct {
	prefix  string
	chinese string
}

const maxTranslateInputRunes = 1024

var (
	translationEntries  []ModTranslationEntry
	containsEntries     []ModTranslationEntry // 只有精确条目（不带 @），给 contains 匹配用
	exactTranslations   map[string]string
	prefixTranslations  []prefixRule
	translationLoaded   bool
	translationMutex   sync.RWMutex
)

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

	exactTranslations = make(map[string]string)
	prefixTranslations = nil
	containsEntries = nil

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, "¨")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			idx := strings.Index(part, "|")
			if idx <= 0 || idx >= len(part)-1 {
				continue
			}
			english := strings.TrimSpace(part[:idx])
			chinese := strings.TrimSpace(part[idx+1:])
			if english == "" || chinese == "" {
				continue
			}

			translationEntries = append(translationEntries, ModTranslationEntry{
				English: english,
				Chinese: chinese,
			})

			lowerEnglish := strings.ToLower(english)
			if strings.HasSuffix(english, "@") {
				prefix := strings.ToLower(english[:len(english)-1])
				prefixTranslations = append(prefixTranslations, prefixRule{prefix: prefix, chinese: chinese})
			} else {
				exactTranslations[lowerEnglish] = chinese
				containsEntries = append(containsEntries, ModTranslationEntry{
					English: lowerEnglish,
					Chinese: chinese,
				})
			}
		}
	}

	// 前缀按长度降序：长前缀优先命中，保证确定性。
	sort.Slice(prefixTranslations, func(i, j int) bool {
		if len(prefixTranslations[i].prefix) != len(prefixTranslations[j].prefix) {
			return len(prefixTranslations[i].prefix) > len(prefixTranslations[j].prefix)
		}
		return prefixTranslations[i].prefix < prefixTranslations[j].prefix
	})

	// contains 条目也按 key 长度降序，长的优先命中。
	sort.Slice(containsEntries, func(i, j int) bool {
		if len(containsEntries[i].English) != len(containsEntries[j].English) {
			return len(containsEntries[i].English) > len(containsEntries[j].English)
		}
		return containsEntries[i].English < containsEntries[j].English
	})
}

// capTranslateInput 限制输入长度，避免恶意输入把 contains 全表扫描打爆。
func capTranslateInput(s string) string {
	r := []rune(s)
	if len(r) > maxTranslateInputRunes {
		r = r[:maxTranslateInputRunes]
	}
	return string(r)
}

func (a *App) TranslateModName(english string) string {
	english = capTranslateInput(english)
	if strings.TrimSpace(english) == "" {
		return english
	}
	loadTranslations()

	translationMutex.RLock()
	defer translationMutex.RUnlock()

	lowerEnglish := strings.ToLower(strings.TrimSpace(english))

	// 精确匹配（O(1)）
	if chinese, ok := exactTranslations[lowerEnglish]; ok {
		return chinese
	}

	// 前缀匹配：已按长度降序排好，命中即返回
	for _, rule := range prefixTranslations {
		if strings.HasPrefix(lowerEnglish, rule.prefix) {
			return rule.chinese
		}
	}

	// 包含匹配：只跑精确条目（@ 条目已在 prefix 阶段处理过），
	// 而且 containsEntries 已按 key 长度降序排好。
	for _, entry := range containsEntries {
		key := entry.English
		if len(key) > 3 && strings.Contains(lowerEnglish, key) {
			return entry.Chinese
		}
	}

	return english
}

func (a *App) SearchModsByChineseName(chineseQuery string) []string {
	chineseQuery = capTranslateInput(chineseQuery)
	if strings.TrimSpace(chineseQuery) == "" {
		return nil
	}
	loadTranslations()

	translationMutex.RLock()
	defer translationMutex.RUnlock()

	query := strings.ToLower(strings.TrimSpace(chineseQuery))
	seen := make(map[string]struct{})
	var results []string

	for _, entry := range translationEntries {
		chineseLower := strings.ToLower(entry.Chinese)
		if strings.Contains(chineseLower, query) {
			if _, ok := seen[entry.English]; ok {
				continue
			}
			seen[entry.English] = struct{}{}
			results = append(results, entry.English)
		}
	}

	return results
}

func (a *App) GetTranslationCount() int {
	loadTranslations()
	translationMutex.RLock()
	defer translationMutex.RUnlock()
	return len(translationEntries)
}

func fuzzyMatch(s, t string) float64 {
	s = strings.ToLower(s)
	t = strings.ToLower(t)
	if s == t {
		return 1.0
	}
	lenS := len(s)
	lenT := len(t)
	if lenS == 0 || lenT == 0 {
		return 0
	}

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
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i][j-1]+cost,
			)
		}
	}
	maxLen := lenS
	if lenT > maxLen {
		maxLen = lenT
	}
	return 1.0 - float64(matrix[lenS][lenT])/float64(maxLen)
}

func min(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}

func isChinese(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

func (a *App) GetModTranslationFileContent() (string, error) {
	data, err := modDataFile.ReadFile("resources/ModData.txt")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (a *App) ReadLicenseFile() string {
	data, err := modDataFile.ReadFile("resources/APACHE_LICENSE.txt")
	if err != nil {
		return ""
	}
	return string(data)
}
