package main

import (
	"bufio"
	"embed"
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

var (
	translationEntries  []ModTranslationEntry
	exactTranslations   map[string]string
	prefixTranslations  map[string]string
	translationLoaded   bool
	translationMutex    sync.RWMutex
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
	prefixTranslations = make(map[string]string)

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
				prefixTranslations[prefix] = chinese
			} else {
				exactTranslations[lowerEnglish] = chinese
			}
		}
	}
}

func (a *App) TranslateModName(english string) string {
	loadTranslations()

	translationMutex.RLock()
	defer translationMutex.RUnlock()

	lowerEnglish := strings.ToLower(strings.TrimSpace(english))

	// 精确匹配（O(1)）
	if chinese, ok := exactTranslations[lowerEnglish]; ok {
		return chinese
	}

	// 前缀匹配
	for prefix, chinese := range prefixTranslations {
		if strings.HasPrefix(lowerEnglish, prefix) {
			return chinese
		}
	}

	// 包含匹配
	for _, entry := range translationEntries {
		if !strings.HasSuffix(entry.English, "@") {
			key := strings.ToLower(entry.English)
			if strings.Contains(lowerEnglish, key) && len(key) > 3 {
				return entry.Chinese
			}
		}
	}

	return english
}

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
				matrix[i-1][j-1]+cost,
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
