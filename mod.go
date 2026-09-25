package main

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// isPathInDir 校验路径是否在指定目录内，防止路径遍历
func isPathInDir(path, dir string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absDir, absPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}

// isValidModID 验证 Mod ID 格式，防止 URL 注入
func isValidModID(id string) bool {
	if len(id) > 100 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ===== Modrinth API 相关结构体 =====

type ModSearchResult struct {
	ProjectID    string   `json:"project_id"`
	Slug         string   `json:"slug"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	IconURL      string   `json:"icon_url"`
	Downloads    int      `json:"downloads"`
	ClientSide   string   `json:"client_side"`
	ServerSide   string   `json:"server_side"`
	Categories   []string `json:"categories"`
	GameVersions []string `json:"game_versions"`
	Loaders      []string `json:"loaders"`
}

type ModSearchResponse struct {
	Hits      []ModSearchResult `json:"hits"`
	TotalHits int               `json:"total_hits"`
	Offset    int               `json:"offset"`
	Limit     int               `json:"limit"`
}

type ModVersion struct {
	ID            string          `json:"id"`
	ProjectID     string          `json:"project_id"`
	Name          string          `json:"name"`
	VersionNumber string          `json:"version_number"`
	GameVersions  []string        `json:"game_versions"`
	Loaders       []string        `json:"loaders"`
	Files         []ModFile       `json:"files"`
	Dependencies  []ModDependency `json:"dependencies"`
	Changelog     string          `json:"changelog"`
}

type ModFile struct {
	Filename string            `json:"filename"`
	URL      string            `json:"url"`
	Size     int64             `json:"size"`
	Primary  bool              `json:"primary"`
	SHA1     string            `json:"sha1"`
	Hashes   map[string]string `json:"hashes"`
}

type ModDependency struct {
	ProjectID      string `json:"project_id"`
	VersionID      string `json:"version_id"`
	DependencyType string `json:"dependency_type"`
}

type ModDetail struct {
	ID           string   `json:"id"`
	Slug         string   `json:"slug"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Body         string   `json:"body"`
	IconURL      string   `json:"icon_url"`
	Downloads    int      `json:"downloads"`
	ClientSide   string   `json:"client_side"`
	ServerSide   string   `json:"server_side"`
	Categories   []string `json:"categories"`
	GameVersions []string `json:"game_versions"`
	Loaders      []string `json:"loaders"`
	ProjectType  string   `json:"project_type"`
}

type ModDependencyInfo struct {
	ProjectID      string `json:"projectId"`
	ProjectName    string `json:"projectName"`
	IconURL        string `json:"iconUrl"`
	DependencyType string `json:"dependencyType"`
}

type ModCategory struct {
	Name        string `json:"name"`
	Icon        string `json:"icon"`
	ProjectType string `json:"project_type"`
}

type ModFileInfo struct {
	FileName  string `json:"fileName"`
	FilePath  string `json:"filePath"`
	IsEnabled bool   `json:"isEnabled"`
	FileSize  int64  `json:"fileSize"`
}

const modrinthBaseURL = "https://api.modrinth.com/v2"

// modExpectedHashes 缓存 Modrinth 给的文件哈希，key 是下载 URL。
// 之前 downloadModItem 下载完根本不校验哈希，镜像源被投毒或 CDN 被中间人替换都不会被发现。
var modExpectedHashes = map[string]map[string]string{}

// recordModHashes 把 Modrinth 给的哈希登记到待校验集合。
func recordModHashes(fileURL string, f ModFile) {
	if fileURL == "" {
		return
	}
	hashes := map[string]string{}
	for k, v := range f.Hashes {
		if v != "" {
			hashes[strings.ToLower(k)] = strings.ToLower(v)
		}
	}
	if f.SHA1 != "" {
		if _, ok := hashes["sha1"]; !ok {
			hashes["sha1"] = strings.ToLower(f.SHA1)
		}
	}
	if len(hashes) > 0 {
		modExpectedHashes[fileURL] = hashes
	}
}

// verifyModDownloaded 用 Modrinth 给的哈希校验刚下载的 mod jar。
// 优先 sha512，缺了再 sha1；都没有就跳过（不阻塞老版本 API 响应）。
func verifyModDownloaded(destPath, fileURL string) error {
	hashes, ok := modExpectedHashes[fileURL]
	if !ok {
		return nil
	}
	f, err := os.Open(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if want, ok := hashes["sha512"]; ok && want != "" {
		h := sha512.New512_256()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		got := hex.EncodeToString(h.Sum(nil))
		if got != want {
			return fmt.Errorf("sha512 校验失败（可能下载被篡改）: got %s want %s", got, want)
		}
		return nil
	}

	if want, ok := hashes["sha1"]; ok && want != "" {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		h := sha1.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		got := hex.EncodeToString(h.Sum(nil))
		if got != want {
			return fmt.Errorf("sha1 校验失败（可能下载被篡改）: got %s want %s", got, want)
		}
		return nil
	}
	return nil
}

// mirrorModURL 将 Mod 下载 URL 替换为中国镜像源
func mirrorModURL(original string) string {
	u := original
	u = strings.Replace(u, "https://cdn.modrinth.com", "https://mod.mcimirror.top/modrinth", 1)
	u = strings.Replace(u, "https://api.modrinth.com", "https://mod.mcimirror.top/modrinth", 1)
	u = strings.Replace(u, "https://edge.forgecdn.net", "https://mod.mcimirror.top/curseforge", 1)
	u = strings.Replace(u, "https://mediafilez.forgecdn.net", "https://mod.mcimirror.top/curseforge", 1)
	return u
}

// SearchMods 搜索 Mod
func (a *App) SearchMods(query string, gameVersion string, loader string, category string, page int, pageSize int) (*ModSearchResponse, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page < 0 {
		page = 0
	}

	params := url.Values{}
	params.Set("query", query)
	params.Set("limit", fmt.Sprintf("%d", pageSize))
	params.Set("offset", fmt.Sprintf("%d", page*pageSize))
	params.Set("index", "relevance")

	var facets []string
	facets = append(facets, `["project_type:mod"]`)

	// 安全校验：过滤非法字符
	if gameVersion != "" && isValidMCVersion(gameVersion) {
		facets = append(facets, fmt.Sprintf(`["versions:%s"]`, gameVersion))
	}
	if loader != "" && isValidModID(loader) {
		facets = append(facets, fmt.Sprintf(`["categories:%s"]`, loader))
	}
	if category != "" && isValidModID(category) {
		facets = append(facets, fmt.Sprintf(`["categories:%s"]`, category))
	}

	if len(facets) > 0 {
		facetsJSON := fmt.Sprintf("[%s]", strings.Join(facets, ","))
		params.Set("facets", facetsJSON)
	}

	apiURL := fmt.Sprintf("%s/search?%s", modrinthBaseURL, params.Encode())

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("搜索 Mod 失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("搜索 Mod 失败: HTTP %d, %s", resp.StatusCode, string(body))
	}

	var result ModSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析搜索结果失败: %v", err)
	}

	if result.Hits == nil {
		result.Hits = []ModSearchResult{}
	}
	for i := range result.Hits {
		if result.Hits[i].Categories == nil {
			result.Hits[i].Categories = []string{}
		}
		if result.Hits[i].GameVersions == nil {
			result.Hits[i].GameVersions = []string{}
		}
		if result.Hits[i].Loaders == nil {
			result.Hits[i].Loaders = []string{}
		}
	}

	return &result, nil
}

// GetModDetail 获取 Mod 详情
func (a *App) GetModDetail(projectID string) (*ModDetail, error) {
	if !isValidModID(projectID) {
		return nil, fmt.Errorf("无效的 Mod ID 格式")
	}

	apiURL := fmt.Sprintf("%s/project/%s", modrinthBaseURL, projectID)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 Mod 详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Mod 详情失败: HTTP %d", resp.StatusCode)
	}

	var detail ModDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, fmt.Errorf("解析 Mod 详情失败: %v", err)
	}

	return &detail, nil
}

// GetModVersions 获取 Mod 版本列表
func (a *App) GetModVersions(projectID string, gameVersion string, loader string) ([]ModVersion, error) {
	if !isValidModID(projectID) {
		return nil, fmt.Errorf("无效的 Mod ID 格式")
	}

	apiURL := fmt.Sprintf("%s/project/%s/version", modrinthBaseURL, projectID)

	params := url.Values{}
	if gameVersion != "" && isValidMCVersion(gameVersion) {
		gvJSON, _ := json.Marshal([]string{gameVersion})
		params.Set("game_versions", string(gvJSON))
	}
	if loader != "" && isValidModID(loader) {
		loaderJSON, _ := json.Marshal([]string{loader})
		params.Set("loaders", string(loaderJSON))
	}

	if len(params) > 0 {
		apiURL += "?" + params.Encode()
	}

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 Mod 版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Mod 版本失败: HTTP %d", resp.StatusCode)
	}

	var versions []ModVersion
	if err := json.NewDecoder(resp.Body).Decode(&versions); err != nil {
		return nil, fmt.Errorf("解析 Mod 版本失败: %v", err)
	}

	if versions == nil {
		versions = []ModVersion{}
	}
	for i := range versions {
		if versions[i].GameVersions == nil {
			versions[i].GameVersions = []string{}
		}
		if versions[i].Loaders == nil {
			versions[i].Loaders = []string{}
		}
		if versions[i].Files == nil {
			versions[i].Files = []ModFile{}
		}
		if versions[i].Dependencies == nil {
			versions[i].Dependencies = []ModDependency{}
		}
	}

	return versions, nil
}

// GetModDependencies 获取 Mod 依赖信息
func (a *App) GetModDependencies(versionID string) ([]ModDependencyInfo, error) {
	if !isValidModID(versionID) {
		return nil, fmt.Errorf("无效的版本 ID 格式")
	}

	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取版本详情失败: HTTP %d", resp.StatusCode)
	}

	var version ModVersion
	if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
		return nil, fmt.Errorf("解析版本详情失败: %v", err)
	}

	var deps []ModDependencyInfo
	if version.Dependencies == nil {
		return deps, nil
	}
	for _, dep := range version.Dependencies {
		if dep.ProjectID == "" {
			continue
		}

		depInfo := ModDependencyInfo{
			ProjectID:      dep.ProjectID,
			DependencyType: dep.DependencyType,
		}

		detail, err := a.GetModDetail(dep.ProjectID)
		if err == nil && detail != nil {
			depInfo.ProjectName = detail.Title
			depInfo.IconURL = detail.IconURL
		} else {
			depInfo.ProjectName = dep.ProjectID
		}

		deps = append(deps, depInfo)
	}

	return deps, nil
}

// AddModToDownloadList 添加 Mod 到下载列表
func (a *App) AddModToDownloadList(versionID string, savePath string) error {
	if !isValidModID(versionID) {
		return fmt.Errorf("无效的版本 ID 格式")
	}

	// 安全校验: savePath必须在.minecraft目录内
	if savePath != "" {
		mcDir := a.GetMinecraftDir()
		if !isPathInDir(savePath, mcDir) {
			return fmt.Errorf("保存路径越界，必须在.minecraft目录内")
		}
	}

	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return fmt.Errorf("获取版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取版本详情失败: HTTP %d", resp.StatusCode)
	}

	var version ModVersion
	if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
		return fmt.Errorf("解析版本详情失败: %v", err)
	}

	var primaryFile *ModFile
	for i := range version.Files {
		if version.Files[i].Primary {
			primaryFile = &version.Files[i]
			break
		}
	}
	if primaryFile == nil && len(version.Files) > 0 {
		primaryFile = &version.Files[0]
	}
	if primaryFile == nil {
		return fmt.Errorf("未找到 Mod 文件")
	}

	// 安全校验：下载 URL 必须是 HTTPS
	if !isHTTPSURL(primaryFile.URL) {
		return fmt.Errorf("不安全的下载 URL（非 HTTPS）")
	}

	// 登记 Modrinth 给的哈希，下载完会校验
	recordModHashes(primaryFile.URL, *primaryFile)

	if savePath == "" {
		mcDir := a.GetMinecraftDir()
		savePath = filepath.Join(mcDir, "mods")
	}

	if err := os.MkdirAll(savePath, 0700); err != nil {
		return fmt.Errorf("创建保存目录失败: %v", err)
	}

	// 安全：使用 filepath.Base 剥离路径遍历组件
	customName := filepath.Base(primaryFile.Filename)
	if customName == "" || customName == "." || customName == string(filepath.Separator) {
		customName = filepath.Base(version.Name)
	}
	if customName == "" || customName == "." {
		customName = "mod.jar"
	}

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在: %s", customName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         versionID,
		URL:        primaryFile.URL,
		CustomName: customName,
		Type:       "mod",
		ItemType:   "mod",
		SavePath:   savePath,
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// ResolveModDependencies 解析 mod 的前置依赖
func (a *App) ResolveModDependencies(versionIDs []string, gameVersion string, loader string) ([]ModDependencyResult, error) {
	var results []ModDependencyResult
	visited := make(map[string]bool)

	for _, vid := range versionIDs {
		if !isValidModID(vid) {
			continue
		}

		apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, vid)
		resp, err := safeHTTPClient().Get(apiURL)
		if err != nil {
			continue
		}
		var version ModVersion
		if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		if version.ProjectID != "" {
			visited[version.ProjectID] = true
		}
	}

	var resolveDeps func(vid string, depth int) error
	resolveDeps = func(vid string, depth int) error {
		if depth > 5 {
			return nil
		}

		if !isValidModID(vid) {
			return nil
		}

		apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, vid)
		resp, err := safeHTTPClient().Get(apiURL)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()

		var version ModVersion
		if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
			return nil
		}

		for _, dep := range version.Dependencies {
			if dep.DependencyType == "optional" || dep.DependencyType == "embedded" {
				continue
			}
			if dep.DependencyType != "required" {
				continue
			}
			if dep.ProjectID == "" {
				continue
			}
			if visited[dep.ProjectID] {
				continue
			}
			visited[dep.ProjectID] = true

			detail, err := a.GetModDetail(dep.ProjectID)
			if err != nil {
				continue
			}

			depVersionID := dep.VersionID
			if depVersionID == "" {
				versions, err := a.GetModVersions(dep.ProjectID, gameVersion, loader)
				if err != nil || len(versions) == 0 {
					continue
				}
				depVersionID = versions[0].ID
			}

			results = append(results, ModDependencyResult{
				ProjectID:      dep.ProjectID,
				ProjectName:    detail.Title,
				IconURL:        detail.IconURL,
				VersionID:      depVersionID,
				DependencyType: dep.DependencyType,
			})

			_ = resolveDeps(depVersionID, depth+1)
		}
		return nil
	}

	for _, vid := range versionIDs {
		_ = resolveDeps(vid, 0)
	}

	return results, nil
}

type ModDependencyResult struct {
	ProjectID      string `json:"projectId"`
	ProjectName    string `json:"projectName"`
	IconURL        string `json:"iconUrl"`
	VersionID      string `json:"versionId"`
	DependencyType string `json:"dependencyType"`
}

// SelectModSaveDir 弹出选择 Mod 保存目录对话框
func (a *App) SelectModSaveDir() (string, error) {
	path, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 Mod 保存位置",
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// GetDefaultModDir 获取默认 Mod 目录
func (a *App) GetDefaultModDir(versionID string) string {
	mcDir := a.GetMinecraftDir()
	if versionID != "" && !strings.Contains(versionID, "..") && !strings.Contains(versionID, "/") && !strings.Contains(versionID, "\\") {
		return filepath.Join(mcDir, "versions", versionID, "mods")
	}
	return filepath.Join(mcDir, "mods")
}

// GetModList 获取指定版本的 Mod 列表
func (a *App) GetModList(versionID string) ([]ModFileInfo, error) {
	if versionID != "" {
		if strings.Contains(versionID, "..") || strings.Contains(versionID, "/") || strings.Contains(versionID, "\\") {
			return nil, fmt.Errorf("版本ID包含非法字符")
		}
	}
	mcDir := a.GetMinecraftDir()
	var modsDir string

	if a.isVersionIsolated() && versionID != "" {
		modsDir = filepath.Join(mcDir, "versions", versionID, "mods")
	} else {
		modsDir = filepath.Join(mcDir, "mods")
	}

	mods := []ModFileInfo{}

	entries, err := os.ReadDir(modsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return mods, nil
		}
		return nil, fmt.Errorf("读取 Mod 目录失败: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		lowerName := strings.ToLower(name)

		isEnabled := true
		if strings.HasSuffix(lowerName, ".jar.disabled") {
			isEnabled = false
		} else if !strings.HasSuffix(lowerName, ".jar") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		mods = append(mods, ModFileInfo{
			FileName:  name,
			FilePath:  filepath.Join(modsDir, name),
			IsEnabled: isEnabled,
			FileSize:  info.Size(),
		})
	}

	return mods, nil
}

// ToggleMod 切换 Mod 启用/禁用状态
func (a *App) ToggleMod(modFilePath string, enable bool) error {
	mcDir := a.GetMinecraftDir()
	if !isPathInDir(modFilePath, mcDir) {
		return fmt.Errorf("文件路径越界，必须在.minecraft目录内")
	}
	if _, err := os.Stat(modFilePath); err != nil {
		return fmt.Errorf("文件不存在: %s", modFilePath)
	}

	var newPath string
	if enable {
		if strings.HasSuffix(strings.ToLower(modFilePath), ".jar.disabled") {
			newPath = modFilePath[:len(modFilePath)-len(".disabled")]
		} else {
			return nil
		}
	} else {
		if strings.HasSuffix(strings.ToLower(modFilePath), ".jar") {
			newPath = modFilePath + ".disabled"
		} else {
			return nil
		}
	}

	if err := os.Rename(modFilePath, newPath); err != nil {
		return fmt.Errorf("重命名失败: %v", err)
	}

	return nil
}

// ImportMod 导入 Mod 文件
func (a *App) ImportMod(versionID string) error {
	if versionID != "" {
		if strings.Contains(versionID, "..") || strings.Contains(versionID, "/") || strings.Contains(versionID, "\\") {
			return fmt.Errorf("版本ID包含非法字符")
		}
	}
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 Mod 文件",
		Filters: []runtime.FileFilter{
			{DisplayName: "Mod 文件 (*.jar)", Pattern: "*.jar"},
		},
	})
	if err != nil || path == "" {
		return nil
	}

	mcDir := a.GetMinecraftDir()
	var modsDir string

	if a.isVersionIsolated() && versionID != "" {
		modsDir = filepath.Join(mcDir, "versions", versionID, "mods")
	} else {
		modsDir = filepath.Join(mcDir, "mods")
	}

	if err := os.MkdirAll(modsDir, 0700); err != nil {
		return fmt.Errorf("创建 Mod 目录失败: %v", err)
	}

	src, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("打开源文件失败: %v", err)
	}
	defer src.Close()

	fileName := filepath.Base(path)
	destPath := filepath.Join(modsDir, fileName)

	if _, err := os.Stat(destPath); err == nil {
		return fmt.Errorf("Mod 文件已存在: %s", fileName)
	}

	dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建目标文件失败: %v", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		os.Remove(destPath)
		return fmt.Errorf("复制文件失败: %v", err)
	}

	return nil
}

// DeleteMod 删除 Mod 文件
func (a *App) DeleteMod(modFilePath string) error {
	mcDir := a.GetMinecraftDir()
	if !isPathInDir(modFilePath, mcDir) {
		return fmt.Errorf("文件路径越界，必须在.minecraft目录内")
	}
	if _, err := os.Stat(modFilePath); err != nil {
		return fmt.Errorf("文件不存在: %s", modFilePath)
	}
	return os.Remove(modFilePath)
}

// downloadModItem 下载 Mod 文件
func (a *App) downloadModItem(item *DownloadItem) error {
	destDir := item.SavePath
	if destDir == "" {
		mcDir := a.GetMinecraftDir()
		destDir = filepath.Join(mcDir, "mods")
	}

	if err := os.MkdirAll(destDir, 0700); err != nil {
		return fmt.Errorf("创建 mods 目录失败: %v", err)
	}

	// 安全：使用 filepath.Base 剥离 API 返回文件名中的路径遍历组件
	fileName := filepath.Base(item.CustomName)
	if fileName == "" || fileName == "." || fileName == string(filepath.Separator) {
		fileName = filepath.Base(item.URL)
	}
	if !strings.HasSuffix(strings.ToLower(fileName), ".jar") {
		fileName += ".jar"
	}

	destPath := filepath.Join(destDir, fileName)

	if _, err := os.Stat(destPath); err == nil {
		return nil
	}

	a.emitProgress("downloading", fileName, 0, 0)

	// 安全校验：下载 URL 必须是 HTTPS
	if !isHTTPSURL(item.URL) {
		return fmt.Errorf("不安全的下载 URL（非 HTTPS）")
	}

	// 先尝试镜像源，失败再回退到官方源
	client := safeHTTPClient()
	resp, err := client.Get(mirrorModURL(item.URL))
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		resp, err = safeHTTPClient().Get(item.URL)
		if err != nil {
			return fmt.Errorf("下载 Mod 失败: %v", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 Mod 失败: HTTP %d", resp.StatusCode)
	}

	out, err := os.OpenFile(destPath+".part", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}

	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 32*1024)

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				os.Remove(destPath + ".part")
				return werr
			}
			downloaded += int64(n)
			a.emitProgress("downloading", fileName, downloaded, total)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			out.Close()
			os.Remove(destPath + ".part")
			return readErr
		}
	}
	out.Close()

	// 关键修复：下载完先用 Modrinth 给的哈希校验，再原子改名。
	// 之前直接 os.Rename 到 destPath，镜像源被投毒/MITM 都不会被发现。
	if err := verifyModDownloaded(destPath+".part", item.URL); err != nil {
		os.Remove(destPath + ".part")
		return fmt.Errorf("Mod 完整性校验失败: %w", err)
	}

	if err := os.Rename(destPath+".part", destPath); err != nil {
		os.Remove(destPath + ".part")
		return fmt.Errorf("重命名临时文件失败: %v", err)
	}

	return nil
}

// GetModrinthCategories 获取 Modrinth 分类标签
func (a *App) GetModrinthCategories() ([]ModCategory, error) {
	apiURL := fmt.Sprintf("%s/tag/category", modrinthBaseURL)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取分类失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取分类失败: HTTP %d", resp.StatusCode)
	}

	var categories []ModCategory
	if err := json.NewDecoder(resp.Body).Decode(&categories); err != nil {
		return nil, fmt.Errorf("解析分类失败: %v", err)
	}

	modCategories := []ModCategory{}
	for _, cat := range categories {
		if cat.ProjectType == "mod" {
			modCategories = append(modCategories, cat)
		}
	}

	return modCategories, nil
}
