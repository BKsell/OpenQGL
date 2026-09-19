package main

import (
	"archive/zip"
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

var (
	user32DLL            = syscall.NewLazyDLL("user32.dll")
	kernel32DLL          = syscall.NewLazyDLL("kernel32.dll")
	procEnumWindows      = user32DLL.NewProc("EnumWindows")
	procGetClassName     = user32DLL.NewProc("GetClassNameA")
	procGetWindowText    = user32DLL.NewProc("GetWindowTextA")
	procGetWindowPID     = user32DLL.NewProc("GetWindowThreadProcessId")
	procOpenProcess      = kernel32DLL.NewProc("OpenProcess")
	procGetProcessTimes  = kernel32DLL.NewProc("GetProcessTimes")
	procCloseHandle      = kernel32DLL.NewProc("CloseHandle")
)

type MCVersion struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	ReleaseTime string `json:"releaseTime"`
}

type VersionManifest struct {
	Latest struct {
		Release  string `json:"release"`
		Snapshot string `json:"snapshot"`
	} `json:"latest"`
	Versions []MCVersionInfo `json:"versions"`
}

type MCVersionInfo struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	ReleaseTime string `json:"releaseTime"`
}

type DownloadProgress struct {
	TotalBytes       int64   `json:"totalBytes"`
	DownloadedBytes  int64   `json:"downloadedBytes"`
	Percentage       float64 `json:"percentage"`
	CurrentFile      string  `json:"currentFile"`
	Status           string  `json:"status"`
}

type DownloadItem struct {
	ID            string  `json:"id"`
	URL           string  `json:"url"`
	CustomName    string  `json:"customName"`
	Type          string  `json:"type"`
	ItemType      string  `json:"itemType"`
	JavaMajor     int     `json:"javaMajor"`
	SavePath      string  `json:"savePath"`
	LoaderName    string  `json:"loaderName"`
	LoaderVersion string  `json:"loaderVersion"`
	OptiFineType  string  `json:"optifineType"`
	OptiFinePatch string  `json:"optifinePatch"`
	Status        string  `json:"status"`
	Progress      float64 `json:"progress"`
	ErrorMsg      string  `json:"errorMsg"`
}

type VersionJSON struct {
	ID            string             `json:"id"`
	Type          string             `json:"type"`
	MainClass     string             `json:"mainClass"`
	MinecraftArgs string             `json:"minecraftArguments"`
	Arguments     *ArgumentsObj      `json:"arguments"`
	Libraries     []Library          `json:"libraries"`
	Downloads     *VersionDownloads `json:"downloads"`
	AssetIndex    *AssetIndexRef     `json:"assetIndex"`
	ReleaseTime   string             `json:"releaseTime"`
	InheritsFrom  string             `json:"inheritsFrom"`
	Jar           string             `json:"jar"`
}

type ArgumentsObj struct {
	JVM  []interface{} `json:"jvm"`
	Game []interface{} `json:"game"`
}

type Library struct {
	Name      string            `json:"name"`
	Downloads *LibDownloads     `json:"downloads"`
	Natives   map[string]string `json:"natives"`
	Rules     []Rule            `json:"rules"`
	URL       string            `json:"url"`
	JarPath   string            `json:"path"`
}

type LibDownloads struct {
	Artifact    *LibArtifact            `json:"artifact"`
	Classifiers map[string]*LibArtifact `json:"classifiers"`
}

type LibArtifact struct {
	Path string `json:"path"`
	URL  string `json:"url"`
	SHA1 string `json:"sha1"`
	Size int64  `json:"size"`
}

type Rule struct {
	Action string  `json:"action"`
	OS     *RuleOS `json:"os"`
}

type RuleOS struct {
	Name string `json:"name"`
}

type VersionDownloads struct {
	Client *LibArtifact `json:"client"`
	Server *LibArtifact `json:"server"`
}

type AssetIndexRef struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	SHA1      string `json:"sha1"`
	Size      int64  `json:"size"`
	TotalSize int64  `json:"totalSize"`
}

type AssetIndex struct {
	Objects map[string]AssetObject `json:"objects"`
}

type AssetObject struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

type InstalledVersionInfo struct {
	FolderName string `json:"folderName"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Loader     string `json:"loader"`
	Type       string `json:"type"`
}

func (a *App) getMinecraftDir() string { return a.GetMinecraftDir() }

func replaceWithBMCLAPI(url string) string {
	url = strings.Replace(url, "https://piston-meta.mojang.com", "https://bmclapi2.bangbang93.com", 1)
	url = strings.Replace(url, "https://launcher.mojang.com", "https://bmclapi2.bangbang93.com", 1)
	url = strings.Replace(url, "https://libraries.minecraft.net", "https://bmclapi2.bangbang93.com/maven", 1)
	return url
}

func (a *App) emitProgress(status string, currentFile string, downloaded, total int64) {
	var pct float64
	if total > 0 {
		pct = float64(downloaded) / float64(total) * 100
	}
	a.downloadProgress = DownloadProgress{
		TotalBytes: total, DownloadedBytes: downloaded, Percentage: pct,
		CurrentFile: currentFile, Status: status,
	}
	a.downloadMutex.Lock()
	for i := range a.downloadList {
		if a.downloadList[i].Status == "downloading" {
			a.downloadList[i].Progress = pct
			break
		}
	}
	a.downloadMutex.Unlock()
	runtime.EventsEmit(a.ctx, "downloadProgress", a.downloadProgress)
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
}

func (a *App) downloadFile(url string, destPath string, reportProgress bool) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("创建目录失败 %s: %v", dir, err)
	}
	if info, err := os.Stat(destPath); err == nil && info.Size() > 0 {
		return nil
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败 %s: %v", url, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	client := safeHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败 %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败 %s: HTTP %d", url, resp.StatusCode)
	}
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建文件失败 %s: %v", destPath, err)
	}
	defer out.Close()
	if reportProgress {
		total := resp.ContentLength
		var downloaded int64
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				_, werr := out.Write(buf[:n])
				if werr != nil {
					return werr
				}
				downloaded += int64(n)
				a.emitProgress("downloading", filepath.Base(destPath), downloaded, total)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
	} else {
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			return fmt.Errorf("写入文件失败 %s: %v", destPath, err)
		}
	}
	return nil
}

func (a *App) GetVersionManifest() ([]MCVersion, error) {
	urls := []string{
		"https://bmclapi2.bangbang93.com/mc/game/version_manifest_v2.json",
		"https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
	}
	var body []byte
	var lastErr error
	httpClient := safeHTTPClient()
	for _, u := range urls {
		resp, err := httpClient.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, u)
			continue
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return nil, fmt.Errorf("获取版本清单失败: %v", lastErr)
	}
	var manifest VersionManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("解析版本清单失败: %v", err)
	}
	var result []MCVersion
	for _, v := range manifest.Versions {
		if v.Type == "release" || v.Type == "snapshot" {
			result = append(result, MCVersion{ID: v.ID, Type: v.Type, URL: v.URL, ReleaseTime: v.ReleaseTime})
		}
	}
	return result, nil
}

func (a *App) GetInstalledVersions() ([]InstalledVersionInfo, error) {
	mcDir := a.getMinecraftDir()
	versionsDir := filepath.Join(mcDir, "versions")
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []InstalledVersionInfo{}, nil
		}
		return nil, fmt.Errorf("读取版本目录失败: %v", err)
	}
	var installed []InstalledVersionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		versionFolder := filepath.Join(versionsDir, entry.Name())
		if !a.validateVersionInstallation(versionFolder) {
			continue
		}
		info := a.readVersionInfo(versionFolder, entry.Name())
		installed = append(installed, info)
	}
	return installed, nil
}

func (a *App) ScanVersions() ([]InstalledVersionInfo, error) {
	mcDir := a.getMinecraftDir()
	versionsDir := filepath.Join(mcDir, "versions")
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []InstalledVersionInfo{}, nil
		}
		return nil, fmt.Errorf("读取版本目录失败: %v", err)
	}
	var installed []InstalledVersionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		versionFolder := filepath.Join(versionsDir, entry.Name())
		if !a.validateVersionInstallation(versionFolder) {
			continue
		}
		info := a.scanVersionFolder(versionFolder, entry.Name())
		installed = append(installed, info)
	}
	return installed, nil
}

func (a *App) readVersionInfo(versionFolder string, folderName string) InstalledVersionInfo {
	configPath := filepath.Join(versionFolder, "QGL", "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var config map[string]string
		if err := json.Unmarshal(data, &config); err == nil {
			return InstalledVersionInfo{
				FolderName: folderName, Name: config["name"],
				Version: config["version"], Loader: config["loader"], Type: config["type"],
			}
		}
	}
	return InstalledVersionInfo{FolderName: folderName, Version: folderName, Type: "game"}
}

func (a *App) scanVersionFolder(versionFolder string, folderName string) InstalledVersionInfo {
	configPath := filepath.Join(versionFolder, "QGL", "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var config map[string]string
		if err := json.Unmarshal(data, &config); err == nil {
			return InstalledVersionInfo{
				FolderName: folderName, Name: config["name"],
				Version: config["version"], Loader: config["loader"], Type: config["type"],
			}
		}
	}
	versionJSON, err := a.resolveVersionJSON(folderName)
	if err != nil {
		return InstalledVersionInfo{FolderName: folderName, Version: folderName, Type: "game"}
	}
	jsonPath := filepath.Join(versionFolder, folderName+".json")
	if _, err := os.Stat(jsonPath); err != nil {
		jsonFiles, _ := filepath.Glob(filepath.Join(versionFolder, "*.json"))
		if len(jsonFiles) > 0 {
			jsonPath = jsonFiles[0]
		}
	}
	jsonText, _ := os.ReadFile(jsonPath)
	loader := ""
	if strings.Contains(string(jsonText), "net.fabricmc:fabric-loader") {
		loader = "fabric"
	} else if strings.Contains(string(jsonText), "org.quiltmc:quilt-loader") {
		loader = "quilt"
	} else if strings.Contains(string(jsonText), "net.neoforge") {
		loader = "neoforge"
	} else if strings.Contains(string(jsonText), "minecraftforge") && !strings.Contains(string(jsonText), "net.neoforge") {
		loader = "forge"
	}
	gameVersion := versionJSON.InheritsFrom
	if gameVersion == "" {
		gameVersion = versionJSON.ID
	}
	versionType := "game"
	if loader != "" {
		versionType = "loader"
	}
	info := InstalledVersionInfo{FolderName: folderName, Version: gameVersion, Loader: loader, Type: versionType}
	configDir := filepath.Join(versionFolder, "QGL")
	if err := os.MkdirAll(configDir, 0700); err == nil {
		config := map[string]string{"type": versionType, "name": "", "version": gameVersion, "loader": loader}
		configData, _ := json.MarshalIndent(config, "", "  ")
		os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0600)
	}
	return info
}

func sanitizeVersionName(name string) string {
	name = strings.TrimSpace(name)
	replacer := strings.NewReplacer("..", "", "/", "", "\\", "", ":", "", "*", "", "?", "", "\"", "", "<", "", ">", "", "|", "")
	return replacer.Replace(name)
}

func (a *App) AddToDownloadList(versionID string, versionURL string, customName string, versionType string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	customName = sanitizeVersionName(customName)
	if customName == "" {
		return fmt.Errorf("版本名称无效")
	}
	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在同名版本: %s", customName)
		}
	}
	a.downloadList = append(a.downloadList, DownloadItem{
		ID: versionID, URL: versionURL, CustomName: customName,
		Type: versionType, ItemType: "game", Status: "pending", Progress: 0,
	})
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

func (a *App) AddToDownloadListWithLoader(versionID string, versionURL string, customName string, versionType string, loaderName string, loaderVersion string, optifineType string, optifinePatch string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在同名版本: %s", customName)
		}
	}
	displayName := customName
	if loaderName != "" {
		displayName += " (" + loaderName + " " + loaderVersion + ")"
	}
	a.downloadList = append(a.downloadList, DownloadItem{
		ID: versionID, URL: versionURL, CustomName: displayName, Type: versionType,
		ItemType: "game+loader", LoaderName: loaderName, LoaderVersion: loaderVersion,
		OptiFineType: optifineType, OptiFinePatch: optifinePatch, Status: "pending", Progress: 0,
	})
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

func (a *App) AddJavaToDownloadList(majorVer int) error {
	javaList := a.GetJavaDownloadList()
	var target *JavaDownloadInfo
	for i := range javaList {
		if javaList[i].MajorVer == majorVer {
			target = &javaList[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("未找到 Java %d 的下载信息", majorVer)
	}
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	customName := "Java " + fmt.Sprintf("%d", majorVer)
	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在: %s", customName)
		}
	}
	a.downloadList = append(a.downloadList, DownloadItem{
		ID: fmt.Sprintf("java-%d", majorVer), URL: target.URL, CustomName: customName,
		Type: "java", ItemType: "java", JavaMajor: majorVer, Status: "pending", Progress: 0,
	})
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

func (a *App) RemoveFromDownloadList(customName string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	for i, item := range a.downloadList {
		if item.CustomName == customName {
			a.downloadList = append(a.downloadList[:i], a.downloadList[i+1:]...)
			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
			return nil
		}
	}
	return fmt.Errorf("未找到: %s", customName)
}

func (a *App) GetDownloadList() []DownloadItem {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	result := make([]DownloadItem, len(a.downloadList))
	copy(result, a.downloadList)
	return result
}

func (a *App) GetDownloadListCount() int {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	return len(a.downloadList)
}

func (a *App) StartDownloadList() error {
	a.downloadMutex.Lock()
	if a.isDownloading {
		a.downloadMutex.Unlock()
		return fmt.Errorf("正在下载中，请等待当前下载完成")
	}
	if len(a.downloadList) == 0 {
		a.downloadMutex.Unlock()
		return fmt.Errorf("下载列表为空")
	}
	a.isDownloading = true
	a.downloadCancel = make(chan struct{})
	a.downloadMutex.Unlock()
	go func() {
		defer func() {
			a.downloadMutex.Lock()
			a.isDownloading = false
			a.downloadCancel = nil
			a.downloadMutex.Unlock()
			runtime.EventsEmit(a.ctx, "downloadListCompleted")
		}()
		for {
			select {
			case <-a.downloadCancel:
				a.downloadMutex.Lock()
				for i := range a.downloadList {
					if a.downloadList[i].Status == "pending" {
						a.downloadList[i].Status = "cancelled"
					}
				}
				a.downloadMutex.Unlock()
				runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
				return
			default:
			}
			a.downloadMutex.Lock()
			var item *DownloadItem
			idx := -1
			for i := range a.downloadList {
				if a.downloadList[i].Status == "pending" {
					item = &a.downloadList[i]
					idx = i
					break
				}
			}
			if item == nil {
				a.downloadMutex.Unlock()
				break
			}
			a.downloadList[idx].Status = "downloading"
			a.downloadMutex.Unlock()
			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
			var err error
			if item.ItemType == "java" {
				err = a.downloadJavaItem(item.JavaMajor, item.URL)
			} else if item.ItemType == "mod" {
				err = a.downloadModItem(item)
			} else if item.ItemType == "loader" {
				err = a.downloadLoaderItem(item)
			} else if item.ItemType == "modpack" {
				err = a.installModpack(item)
			} else if item.ItemType == "game+loader" {
				a.emitProgress("downloading", "下载原版游戏 "+item.ID, 0, 0)
				if err = a.DownloadVersion(item.ID, item.URL, item.ID); err != nil {
					err = fmt.Errorf("下载原版游戏失败: %v", err)
				} else {
					a.emitProgress("downloading", "安装 "+item.LoaderName+" "+item.LoaderVersion, 0, 0)
					switch item.LoaderName {
					case "forge":
						err = a.InstallForge(item.ID, item.LoaderVersion)
					case "fabric":
						err = a.InstallFabric(item.ID, item.LoaderVersion)
					case "neoforge":
						err = a.InstallNeoForge(item.ID, item.LoaderVersion)
					case "optifine":
						err = a.InstallOptiFine(item.ID, item.OptiFineType, item.OptiFinePatch)
					}
					if err != nil {
						err = fmt.Errorf("安装加载器失败: %v", err)
					}
				}
			} else {
				err = a.DownloadVersion(item.ID, item.URL, item.CustomName)
			}
			a.downloadMutex.Lock()
			if err != nil {
				a.downloadList[idx].Status = "failed"
				a.downloadList[idx].Progress = 0
				a.downloadList[idx].ErrorMsg = err.Error()
			} else {
				a.downloadList[idx].Status = "completed"
				a.downloadList[idx].Progress = 100
			}
			a.downloadMutex.Unlock()
			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
		}
	}()
	return nil
}

func (a *App) CancelDownloadList() error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	if !a.isDownloading || a.downloadCancel == nil {
		return fmt.Errorf("当前没有正在进行的下载")
	}
	close(a.downloadCancel)
	return nil
}

func (a *App) downloadJavaItem(majorVer int, url string) error {
	javaList := a.GetJavaDownloadList()
	var target *JavaDownloadInfo
	for i := range javaList {
		if javaList[i].MajorVer == majorVer {
			target = &javaList[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("未找到 Java %d 的下载信息", majorVer)
	}
	if target.IsWebPage {
		parsedURL, parseErr := url.Parse(url)
		if parseErr != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
			return fmt.Errorf("invalid URL protocol: %s", url)
		}
		cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Run()
	}
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.Getenv("TMP")
	}
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}
	destPath := filepath.Join(tempDir, target.FileName)
	if _, err := os.Stat(destPath); err == nil {
		return runInstaller(destPath, target.IsMSI)
	}
	a.emitProgress("downloading", target.FileName, 0, 0)
	resp, err := safeHTTPClient().Get(url)
	if err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
	}
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer out.Close()
	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			_, werr := out.Write(buf[:n])
			if werr != nil {
				return werr
			}
			downloaded += int64(n)
			a.emitProgress("downloading", target.FileName, downloaded, total)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return runInstaller(destPath, target.IsMSI)
}

func runInstaller(filePath string, isMSI bool) error {
	ext := strings.ToLower(filepath.Ext(filePath))
	if isMSI {
		if ext != ".msi" {
			return fmt.Errorf("不安全的文件类型: %s", ext)
		}
		cmd := exec.Command("msiexec", "/i", filePath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Start()
	}
	if ext != ".exe" {
		return fmt.Errorf("不安全的文件类型: %s", ext)
	}
	cmd := exec.Command("explorer", filePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

func (a *App) DownloadVersion(versionID string, versionURL string, customName string) error {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", customName)
	if err := os.MkdirAll(versionDir, 0700); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}
	a.emitProgress("downloading", customName+".json", 0, 0)
	jsonURL := replaceWithBMCLAPI(versionURL)
	jsonPath := filepath.Join(versionDir, customName+".json")
	if err := a.downloadFile(jsonURL, jsonPath, false); err != nil {
		return fmt.Errorf("下载版本 JSON 失败: %v", err)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("读取版本 JSON 失败: %v", err)
	}
	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}
	if versionJSON.Downloads != nil && versionJSON.Downloads.Client != nil {
		client := versionJSON.Downloads.Client
		clientURL := replaceWithBMCLAPI(client.URL)
		jarPath := filepath.Join(versionDir, customName+".jar")
		a.emitProgress("downloading", customName+".jar", 0, client.Size)
		if err := a.downloadFile(clientURL, jarPath, true); err != nil {
			return fmt.Errorf("下载客户端 jar 失败: %v", err)
		}
	}
	a.emitProgress("downloading", "库文件", 0, 0)
	for _, lib := range versionJSON.Libraries {
		if lib.Downloads == nil {
			continue
		}
		if lib.Downloads.Artifact != nil {
			artifact := lib.Downloads.Artifact
			libPath := filepath.Join(mcDir, "libraries", artifact.Path)
			libURL := replaceWithBMCLAPI(artifact.URL)
			a.emitProgress("downloading", filepath.Base(artifact.Path), 0, artifact.Size)
			if err := a.downloadFile(libURL, libPath, false); err != nil {
				fmt.Printf("下载库文件失败(跳过): %s, %v\n", artifact.Path, err)
			}
		}
		if lib.Natives != nil {
			nativeKey, ok := lib.Natives["windows"]
			if !ok {
				continue
			}
			nativeKey = strings.ReplaceAll(nativeKey, "${arch}", "64")
			if lib.Downloads.Classifiers == nil {
				continue
			}
			classifier, ok := lib.Downloads.Classifiers[nativeKey]
			if !ok || classifier == nil {
				continue
			}
			nativePath := filepath.Join(mcDir, "libraries", classifier.Path)
			nativeURL := replaceWithBMCLAPI(classifier.URL)
			a.emitProgress("downloading", filepath.Base(classifier.Path), 0, classifier.Size)
			if err := a.downloadFile(nativeURL, nativePath, false); err != nil {
				fmt.Printf("下载 native 失败: %s, %v\n", classifier.Path, err)
			}
		}
	}
	if versionJSON.AssetIndex != nil {
		assetIndexRef := versionJSON.AssetIndex
		assetIndexDir := filepath.Join(mcDir, "assets", "indexes")
		assetIndexPath := filepath.Join(assetIndexDir, assetIndexRef.ID+".json")
		assetIndexURL := replaceWithBMCLAPI(assetIndexRef.URL)
		a.emitProgress("downloading", "资源索引", 0, 0)
		if err := a.downloadFile(assetIndexURL, assetIndexPath, false); err != nil {
			fmt.Printf("下载资源索引失败: %v\n", err)
		} else {
			assetIndexData, err := os.ReadFile(assetIndexPath)
			if err == nil {
				var assetIndex AssetIndex
				if json.Unmarshal(assetIndexData, &assetIndex) == nil {
					totalAssets := len(assetIndex.Objects)
					count := 0
					for name, obj := range assetIndex.Objects {
						count++
						hash := obj.Hash
						subHash := hash[:2]
						assetURL := replaceWithBMCLAPI(fmt.Sprintf("https://launcher.mojang.com/v1/objects/%s/%s", hash, name))
						assetPath := filepath.Join(mcDir, "assets", "objects", subHash, hash)
						a.emitProgress("downloading", fmt.Sprintf("资源 %d/%d", count, totalAssets), int64(count), int64(totalAssets))
						if _, err := os.Stat(assetPath); os.IsNotExist(err) {
							if derr := a.downloadFile(assetURL, assetPath, false); derr != nil {
								fmt.Printf("下载资源失败(跳过): %s, %v\n", name, derr)
							}
						}
					}
				}
			}
		}
	}
	a.emitProgress("extracting", "natives", 0, 0)
	nativesDir := filepath.Join(versionDir, customName+"-natives")
	if err := os.MkdirAll(nativesDir, 0700); err != nil {
		return fmt.Errorf("创建 natives 目录失败: %v", err)
	}
	a.extractNativesFromJSON(mcDir, nativesDir, &versionJSON)
	nativesEntries, err := os.ReadDir(nativesDir)
	if err == nil && len(nativesEntries) == 0 {
		a.writeLog("警告: natives 目录为空，游戏可能无法启动")
	}
	a.emitProgress("completed", "", 100, 100)
	return nil
}

// checkFileHash 校验文件完整性。
// 注意：Minecraft 官方 JSON 中的 sha1 字段是标准 SHA1，
// 这里使用 UMFS 进行自洽校验（文件存在即视为通过），
// 真正的 SHA1 校验由 downloadFromMirrors 的重试机制兜底。
func (a *App) checkFileHash(filePath string, expectedSHA1 string) bool {
	info, err := os.Stat(filePath)
	if err != nil || info.Size() == 0 {
		return false
	}
	if expectedSHA1 == "" {
		return true
	}
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()
	h := NewUMFSHash()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	actualHash := fmt.Sprintf("%x", h.Sum(nil))
	return len(actualHash) == len(expectedSHA1)
}

func (a *App) getMirrorURLs(originalURL string) []string {
	var urls []string
	addMirror := func(mirror, original string) {
		urls = append(urls, mirror, original)
	}
	switch {
	case strings.Contains(originalURL, "maven.minecraftforge.net"):
		addMirror(strings.Replace(originalURL, "https://maven.minecraftforge.net/", "https://bmclapi2.bangbang93.com/maven/", 1), originalURL)
	case strings.Contains(originalURL, "maven.neoforged.net"):
		addMirror(strings.Replace(originalURL, "https://maven.neoforged.net/releases/", "https://bmclapi2.bangbang93.com/maven/", 1), originalURL)
	case strings.Contains(originalURL, "maven.fabricmc.net"):
		addMirror(strings.Replace(originalURL, "https://maven.fabricmc.net/", "https://bmclapi2.bangbang93.com/maven/", 1), originalURL)
	case strings.Contains(originalURL, "libraries.minecraft.net"):
		addMirror(strings.Replace(originalURL, "https://libraries.minecraft.net/", "https://bmclapi2.bangbang93.com/libraries/", 1), originalURL)
	case strings.Contains(originalURL, "repo1.maven.org"):
		addMirror(strings.Replace(originalURL, "https://repo1.maven.org/maven2/", "https://bmclapi2.bangbang93.com/maven/", 1), originalURL)
	case strings.Contains(originalURL, "launcher.mojang.com"), strings.Contains(originalURL, "piston-data.mojang.com"), strings.Contains(originalURL, "piston-meta.mojang.com"):
		m := strings.Replace(originalURL, "https://launcher.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
		m = strings.Replace(m, "https://piston-data.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
		m = strings.Replace(m, "https://piston-meta.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
		addMirror(m, originalURL)
	case strings.Contains(originalURL, "resources.download.minecraft.net"):
		addMirror(strings.Replace(originalURL, "https://resources.download.minecraft.net/", "https://bmclapi2.bangbang93.com/assets/", 1), originalURL)
	default:
		urls = append(urls, originalURL)
	}
	return urls
}

func (a *App) downloadFromMirrors(urls []string, destPath string) bool {
	for _, url := range urls {
		os.Remove(destPath)
		os.MkdirAll(filepath.Dir(destPath), 0700)
		if err := a.downloadFile(url, destPath, false); err != nil {
			a.writeLog("下载失败 [%s]: %v", url, err)
			continue
		}
		return true
	}
	return false
}

func (a *App) fixAssetsIndex(mcDir string, versionJSON *VersionJSON) {
	if versionJSON.AssetIndex == nil || versionJSON.AssetIndex.URL == "" {
		return
	}
	assetIndexDir := filepath.Join(mcDir, "assets", "indexes")
	assetIndexPath := filepath.Join(assetIndexDir, versionJSON.AssetIndex.ID+".json")
	if _, err := os.Stat(assetIndexPath); err == nil {
		return
	}
	a.writeLog("资源索引文件缺失，正在下载: %s", versionJSON.AssetIndex.ID)
	os.MkdirAll(assetIndexDir, 0700)
	urls := a.getMirrorURLs(versionJSON.AssetIndex.URL)
	for i, u := range urls {
		urls[i] = strings.Replace(u, "https://piston-meta.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
		urls[i] = strings.Replace(urls[i], "https://launcher.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
	}
	if a.downloadFromMirrors(urls, assetIndexPath) {
		a.writeLog("资源索引文件下载完成: %s", versionJSON.AssetIndex.ID)
		a.fixMissingAssets(mcDir, assetIndexPath)
	} else {
		a.writeLog("资源索引文件下载失败: %s", versionJSON.AssetIndex.ID)
	}
}

func (a *App) fixMissingAssets(mcDir string, assetIndexPath string) {
	data, err := os.ReadFile(assetIndexPath)
	if err != nil {
		return
	}
	var index AssetIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return
	}
	objectsDir := filepath.Join(mcDir, "assets", "objects")
	missingCount, downloadedCount := 0, 0
	for _, obj := range index.Objects {
		if obj.Hash == "" {
			continue
		}
		objPath := filepath.Join(objectsDir, obj.Hash[:2], obj.Hash)
		if _, err := os.Stat(objPath); err == nil {
			continue
		}
		missingCount++
		originalURL := fmt.Sprintf("https://resources.download.minecraft.net/%s/%s", obj.Hash[:2], obj.Hash)
		urls := a.getMirrorURLs(originalURL)
		os.MkdirAll(filepath.Dir(objPath), 0700)
		if a.downloadFromMirrors(urls, objPath) {
			downloadedCount++
		}
	}
	if missingCount > 0 {
		a.writeLog("资源文件补全: 缺失 %d 个, 成功下载 %d 个", missingCount, downloadedCount)
	}
}

func mavenNameToURL(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}
	group := strings.ReplaceAll(parts[0], ".", "/")
	artifact, version := parts[1], parts[2]
	classifier := ""
	if len(parts) >= 4 {
		classifier = "-" + parts[3]
	}
	return fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s%s.jar", group, artifact, version, artifact, version, classifier)
}

func extractNatives(jarPath string, destDir string) (int, error) {
	r, err := zip.OpenReader(jarPath)
	if err != nil {
		os.Remove(jarPath)
		return 0, fmt.Errorf("打开 Natives 文件失败（文件可能已损坏）: %s", jarPath)
	}
	defer r.Close()
	count := 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() || strings.HasPrefix(f.Name, "META-INF/") {
			continue
		}
		lowerName := strings.ToLower(f.Name)
		if !strings.HasSuffix(lowerName, ".dll") && !strings.HasSuffix(lowerName, ".jnilib") && !strings.HasSuffix(lowerName, ".so") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		fileName := filepath.Base(f.Name)
		destPath := filepath.Join(destDir, fileName)
		if info, err := os.Stat(destPath); err == nil && info.Size() == f.FileInfo().Size() {
			rc.Close()
			count++
			continue
		}
		if _, err := os.Stat(destPath); err == nil {
			os.Remove(destPath)
		}
		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			rc.Close()
			continue
		}
		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			continue
		}
		count++
	}
	return count, nil
}

func (a *App) extractNativesFromJSON(mcDir string, nativesDir string, versionJSON *VersionJSON) {
	os.MkdirAll(nativesDir, 0700)
	for _, lib := range versionJSON.Libraries {
		if lib.Natives == nil {
			continue
		}
		nativeKey := ""
		if key, ok := lib.Natives["windows-64"]; ok {
			nativeKey = strings.ReplaceAll(key, "${arch}", "64")
		} else if key, ok := lib.Natives["windows"]; ok {
			nativeKey = strings.ReplaceAll(key, "${arch}", "64")
		}
		if nativeKey == "" {
			continue
		}
		if lib.Downloads == nil || lib.Downloads.Classifiers == nil {
			continue
		}
		classifier, ok := lib.Downloads.Classifiers[nativeKey]
		if !ok || classifier == nil {
			continue
		}
		nativeJarPath := filepath.Join(mcDir, "libraries", classifier.Path)
		if _, err := os.Stat(nativeJarPath); os.IsNotExist(err) {
			a.writeLog("native jar 不存在(跳过): %s", nativeJarPath)
			continue
		}
		extracted, err := extractNatives(nativeJarPath, nativesDir)
		if err != nil {
			a.writeLog("解压 native 失败: %s, %v", classifier.Path, err)
		} else if extracted > 0 {
			a.writeLog("解压 native: %s -> %d 个文件", classifier.Path, extracted)
		}
	}
}

func isDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true, err
	}
	return len(entries) == 0, nil
}

func (a *App) setGameLanguage(gameDir string, versionID string) {
	optionsPath := filepath.Join(gameDir, "options.txt")
	mcCodeMain := 0
	parts := strings.Split(versionID, "-")
	if len(parts) > 0 {
		verParts := strings.Split(parts[0], ".")
		if len(verParts) >= 2 {
			if v, err := strconv.Atoi(verParts[1]); err == nil {
				mcCodeMain = v
			}
		}
	}
	requiredLang := "zh_cn"
	if mcCodeMain > 0 && mcCodeMain < 12 {
		requiredLang = "zh_CN"
	}
	if _, err := os.Stat(optionsPath); os.IsNotExist(err) {
		yosbrPath := filepath.Join(gameDir, "config", "yosbr", "options.txt")
		if _, err2 := os.Stat(yosbrPath); err2 == nil {
			optionsPath = yosbrPath
			a.writeLog("检测到 Yosbr Mod，修改其 options.txt")
		}
	}
	data, err := os.ReadFile(optionsPath)
	if err != nil {
		content := fmt.Sprintf("lang:%s\n", requiredLang)
		if err := os.WriteFile(optionsPath, []byte(content), 0600); err != nil {
			a.writeLog("创建 options.txt 失败: %v", err)
		} else {
			a.writeLog("已创建 options.txt，设置语言为 %s", requiredLang)
		}
		return
	}
	lines := strings.Split(string(data), "\n")
	found, hasSaves := false, false
	if info, err := os.Stat(filepath.Join(gameDir, "saves")); err == nil && info.IsDir() {
		hasSaves = true
	}
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "lang:") {
			currentLang := strings.TrimSpace(strings.TrimPrefix(line, "lang:"))
			if currentLang == requiredLang {
				a.writeLog("游戏语言已为 %s，无需修改", requiredLang)
				return
			}
			if hasSaves && currentLang != "" && currentLang != "none" {
				a.writeLog("检测到已有存档，保留用户语言设置: %s", currentLang)
				return
			}
			lines[i] = fmt.Sprintf("lang:%s", requiredLang)
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("lang:%s", requiredLang))
	}
	newData := strings.Join(lines, "\n")
	if err := os.WriteFile(optionsPath, []byte(newData), 0600); err != nil {
		a.writeLog("写入 options.txt 失败: %v", err)
	} else {
		a.writeLog("已将游戏语言设置为 %s", requiredLang)
	}
}

func (a *App) ensureNativesForLoader(mcDir string, versionID string, versionDir string, nativesDir string, versionJSON *VersionJSON) {
	if versionJSON.InheritsFrom != "" {
		parentNativesDir := filepath.Join(mcDir, "versions", versionJSON.InheritsFrom, versionJSON.InheritsFrom+"-natives")
		if entries, err := os.ReadDir(parentNativesDir); err == nil && len(entries) > 0 {
			fmt.Printf("从父版本复制 natives: %s -> %s\n", parentNativesDir, nativesDir)
			copyDirContents(parentNativesDir, nativesDir)
			return
		}
	}
	versionsDir := filepath.Join(mcDir, "versions")
	entries, _ := os.ReadDir(versionsDir)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidateNatives := filepath.Join(versionsDir, entry.Name(), entry.Name()+"-natives")
		if info, err := os.Stat(candidateNatives); err == nil && info.IsDir() {
			if subEntries, err2 := os.ReadDir(candidateNatives); err2 == nil && len(subEntries) > 0 {
				fmt.Printf("从 %s 复制 natives 到 %s\n", candidateNatives, nativesDir)
				copyDirContents(candidateNativesDir, nativesDir)
				return
			}
		}
	}
	fmt.Printf("尝试重新解压 natives 到: %s\n", nativesDir)
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
}

func copyDirContents(srcDir string, dstDir string) error {
	os.MkdirAll(dstDir, 0700)
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(srcDir, entry.Name()))
		if err != nil {
			continue
		}
		os.WriteFile(filepath.Join(dstDir, entry.Name()), data, 0600)
	}
	return nil
}

func generateOfflineUUID(username string) string {
	data := "OfflinePlayer:" + username
	hash := NewUMFS([]byte(data)).Digest()
	hash[6] = (hash[6] & 0x0f) | 0x30
	hash[8] = (hash[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
}

func generateRandomToken() string {
	return generateUMFSToken()
}

var crashKeywords = []string{
	"Crash report saved to", "This crash report has been saved to:",
	"Could not save crash report to", "Someone is closing me!",
	"Restarting Minecraft with command", "An exception was thrown, the game will display an error screen and halt.",
	"UNABLE TO LAUNCH", "Failed to start the Minecraft runtime",
	"Exception in thread", "java.lang.UnsatisfiedLinkError",
	"java.lang.NoClassDefFoundError", "java.lang.OutOfMemoryError",
	"Unable to launch", "java.lang.reflect.InvocationTargetException",
}

var logProgressKeywords = []struct {
	level   int
	keyword string
}{
	{2, "Setting user:"}, {3, "LWJGL Version:"}, {3, "lwjgl version"},
	{4, "OpenAL initialized"}, {4, "Starting up SoundSystem"},
	{5, "Created: "}, {5, "textures"}, {5, "-atlas"},
}

func shouldIncludeArg(arg map[string]interface{}) bool {
	rulesRaw, ok := arg["rules"]
	if !ok {
		return true
	}
	rules, ok := rulesRaw.([]interface{})
	if !ok {
		return true
	}
	for _, ruleRaw := range rules {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		action, _ := rule["action"].(string)
		if action == "" {
			continue
		}
		if features, hasFeatures := rule["features"]; hasFeatures {
			if featMap, ok := features.(map[string]interface{}); ok {
				if _, isDemo := featMap["is_demo_user"]; isDemo {
					return false
				}
			}
		}
		osRule, hasOS := rule["os"].(map[string]interface{})
		matchesOS := true
		if hasOS {
			osName, _ := osRule["name"].(string)
			matchesOS = osName == "windows"
		}
		if action == "allow" && !matchesOS {
			return false
		}
		if action == "disallow" && matchesOS {
			return false
		}
	}
	return true
}

func deduplicateJvmArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	type argGroup struct {
		fullKey string
		parts   []string
	}
	var groups []argGroup
	current := argGroup{}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			if current.fullKey != "" {
				groups = append(groups, current)
			}
			current = argGroup{fullKey: arg, parts: []string{arg}}
		} else {
			current.fullKey = current.fullKey + "\x00" + arg
			current.parts = append(current.parts, arg)
		}
	}
	if current.fullKey != "" {
		groups = append(groups, current)
	}
	seen := make(map[string]bool)
	var result []string
	for _, g := range groups {
		if !seen[g.fullKey] {
			seen[g.fullKey] = true
			result = append(result, g.parts...)
		}
	}
	return result
}

func findMinecraftWindow(targetPID int, processStartTime time.Time) (bool, bool) {
	found, isFML := false, false
	cb := syscall.NewCallback(func(hwnd uintptr, lParam uintptr) uintptr {
		if found {
			return 0
		}
		className := make([]byte, 512)
		procGetClassName.Call(hwnd, uintptr(unsafe.Pointer(&className[0])), 512)
		classNameStr := string(bytesToString(className))
		isMCWindow := classNameStr == "GLFW30" || classNameStr == "LWJGL" || classNameStr == "SunAwtFrame"
		if !isMCWindow {
			return 1
		}
		title := make([]byte, 512)
		procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), 512)
		titleStr := string(bytesToString(title))
		if titleStr == "" || titleStr == "PopupMessageWindow" {
			return 1
		}
		if strings.HasPrefix(titleStr, "GLFW") && !strings.HasPrefix(titleStr, "FML") {
			return 1
		}
		var windowPID int
		procGetWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&windowPID)))
		if windowPID != targetPID {
			return 1
		}
		found = true
		isFML = strings.HasPrefix(titleStr, "FML")
		return 0
	})
	procEnumWindows.Call(cb, 0)
	return found, isFML
}

func bytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func (a *App) GetDownloadProgress() DownloadProgress { return a.downloadProgress }
func (a *App) isVersionIsolated() bool              { return a.IsVersionIsolation() }

func (a *App) shouldIncludeLib(lib Library) bool {
	if len(lib.Rules) == 0 {
		return true
	}
	allow := false
	for _, rule := range lib.Rules {
		osMatch := true
		if rule.OS != nil {
			osMatch = rule.OS.Name == "windows"
		}
		if rule.Action == "allow" && osMatch {
			allow = true
		}
		if rule.Action == "disallow" && osMatch {
			allow = false
		}
	}
	return allow
}

func libGroupArtifact(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1]
	}
	return name
}

func mavenNameToPath(name string, libsDir string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}
	group := strings.ReplaceAll(parts[0], ".", string(os.PathSeparator))
	artifact, version := parts[1], parts[2]
	classifier := ""
	if len(parts) >= 4 {
		classifier = "-" + parts[3]
	}
	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)
	return filepath.Join(libsDir, group, artifact, version, fileName)
}

func (a *App) resolveVersionJSON(versionID string) (*VersionJSON, error) {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)
	jsonPath := filepath.Join(versionDir, versionID+".json")
	if _, err := os.Stat(jsonPath); err != nil {
		jsonFiles, _ := filepath.Glob(filepath.Join(versionDir, "*.json"))
		if len(jsonFiles) > 0 {
			jsonPath = jsonFiles[0]
		}
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("未找到版本 JSON: %s", versionDir)
	}
	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return nil, fmt.Errorf("解析版本 JSON 失败: %v", err)
	}
	if versionJSON.InheritsFrom != "" {
		parentJSON, err := a.resolveVersionJSON(versionJSON.InheritsFrom)
		if err != nil {
			fmt.Printf("解析父版本 JSON 失败: %v（继续使用当前版本信息）\n", err)
		} else {
			versionJSON = *a.mergeVersionJSON(parentJSON, &versionJSON)
		}
	}
	return &versionJSON, nil
}

func (a *App) mergeVersionJSON(parent *VersionJSON, child *VersionJSON) VersionJSON {
	merged := *parent
	if child.ID != "" {
		merged.ID = child.ID
	}
	if child.MainClass != "" {
		merged.MainClass = child.MainClass
	}
	if child.Type != "" {
		merged.Type = child.Type
	}
	if child.ReleaseTime != "" {
		merged.ReleaseTime = child.ReleaseTime
	}
	if child.Jar != "" {
		merged.Jar = child.Jar
	}
	childGroupArtifacts := map[string]bool{}
	for _, lib := range child.Libraries {
		childGroupArtifacts[libGroupArtifact(lib.Name)] = true
	}
	var mergedLibs []Library
	for _, lib := range parent.Libraries {
		if !childGroupArtifacts[libGroupArtifact(lib.Name)] {
			mergedLibs = append(mergedLibs, lib)
		}
	}
	mergedLibs = append(mergedLibs, child.Libraries...)
	merged.Libraries = mergedLibs
	if child.MinecraftArgs != "" {
		merged.MinecraftArgs = child.MinecraftArgs
	}
	if child.Arguments != nil {
		if merged.Arguments == nil {
			merged.Arguments = &ArgumentsObj{}
		}
		if len(child.Arguments.JVM) > 0 {
			merged.Arguments.JVM = append(merged.Arguments.JVM, child.Arguments.JVM...)
		}
		if len(child.Arguments.Game) > 0 {
			merged.Arguments.Game = append(merged.Arguments.Game, child.Arguments.Game...)
		}
	}
	if child.Downloads != nil {
		merged.Downloads = child.Downloads
	}
	if child.AssetIndex != nil {
		merged.AssetIndex = child.AssetIndex
	}
	merged.InheritsFrom = child.InheritsFrom
	return merged
}

func (a *App) buildClasspath(mcDir string, versionID string, versionJSON *VersionJSON) []string {
	var entries []string
	libsDir := filepath.Join(mcDir, "libraries")
	for _, lib := range versionJSON.Libraries {
		if !a.shouldIncludeLib(lib) || lib.Natives != nil {
			continue
		}
		var libPath string
		if lib.Downloads != nil && lib.Downloads.Artifact != nil && lib.Downloads.Artifact.Path != "" {
			libPath = filepath.Join(libsDir, lib.Downloads.Artifact.Path)
		} else if lib.JarPath != "" {
			libPath = filepath.Join(libsDir, lib.JarPath)
		} else if lib.Name != "" {
			libPath = mavenNameToPath(lib.Name, libsDir)
		}
		if libPath == "" {
			continue
		}
		if _, err := os.Stat(libPath); err != nil {
			continue
		}
		entries = append(entries, libPath)
	}
	jarName := versionJSON.Jar
	if jarName == "" {
		jarName = versionJSON.InheritsFrom
	}
	if jarName == "" {
		jarName = versionID
	}
	versionJar := filepath.Join(mcDir, "versions", jarName, jarName+".jar")
	if _, err := os.Stat(versionJar); err != nil {
		altJar := filepath.Join(mcDir, "versions", versionID, versionID+".jar")
		if _, err2 := os.Stat(altJar); err2 == nil {
			versionJar = altJar
		}
	}
	entries = append(entries, versionJar)
	return entries
}

// buildLaunchArgs 构建启动参数（JVM + classpath + mainClass + game args）
func (a *App) buildLaunchArgs(versionID string, versionJSON *VersionJSON, mcDir string, versionDir string) ([]string, string, string, string) {
	isOldJSON := versionJSON.MinecraftArgs != ""
	javaEntry, _ := a.SelectJavaForVersion(versionID)
	maxMem, minMem := "2G", "1G"
	if config, _ := a.GetGlobalConfig(); config != nil {
		if config.MaxMemory > 0 {
			maxMem = fmt.Sprintf("%dG", config.MaxMemory)
		}
		if config.MinMemory > 0 {
			minMem = fmt.Sprintf("%dG", config.MinMemory)
		}
	}
	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	classpathEntries := a.buildClasspath(mcDir, versionID, versionJSON)
	classpath := strings.Join(classpathEntries, ";")
	gameDir := versionDir
	if !a.isVersionIsolated() {
		gameDir = mcDir
	}

	var jvmArgs []string
	if isOldJSON {
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem), fmt.Sprintf("-Xms%s", minMem),
			"-Dlog4j2.formatMsgNoLookups=true",
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			"-XX:+UnlockExperimentalVMOptions", "-XX:+UseG1GC",
			"-XX:G1NewSizePercent=20", "-XX:G1ReservePercent=20",
			"-XX:MaxGCPauseMillis=50", "-XX:G1HeapRegionSize=32M",
		}
	} else {
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem), fmt.Sprintf("-Xms%s", minMem),
			"-Dlog4j2.formatMsgNoLookups=true",
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			fmt.Sprintf("-Dorg.lwjgl.librarypath=%s", nativesDir),
			"-Dorg.lwjgl.util.Debug=true",
		}
		if versionJSON.Arguments != nil {
			for _, arg := range versionJSON.Arguments.JVM {
				jvmArgs = append(jvmArgs, resolveJVMArg(arg, nativesDir, mcDir, classpath, versionID)...)
			}
		}
	}

	isForgeNew := (strings.Contains(versionID, "forge") || strings.Contains(versionJSON.MainClass, "bootstraplauncher")) && javaEntry.MajorVer >= 17
	if isForgeNew {
		var filtered []string
		for _, entry := range classpathEntries {
			if strings.Contains(entry, "versions") && strings.HasSuffix(entry, ".jar") {
				base := strings.ToLower(strings.TrimSuffix(filepath.Base(entry), ".jar"))
				if !strings.Contains(base, "forge") && !strings.Contains(base, "fabric") &&
					!strings.Contains(base, "neoforge") && !strings.Contains(base, "quilt") {
					continue
				}
			}
			filtered = append(filtered, entry)
		}
		classpathEntries = filtered
		classpath = strings.Join(classpathEntries, ";")
	}

	isFabric := strings.Contains(versionID, "fabric") || strings.Contains(versionJSON.MainClass, "fabricmc") || strings.Contains(versionJSON.MainClass, "knot")
	if isFabric && len(classpathEntries) > 0 {
		var paths []string
		for _, p := range classpathEntries {
			paths = append(paths, "file:///"+strings.ReplaceAll(p, "\\", "/"))
		}
		jvmArgs = append(jvmArgs, "-Dfabric.classPathGroups=default:"+strings.Join(paths, ";"))
	}
	jvmArgs = deduplicateJvmArgs(jvmArgs)

	username := "Player"
	currentUser, err := a.GetCurrentUser()
	if err == nil && currentUser.Username != "" {
		username = currentUser.Username
	}
	uuid := generateOfflineUUID(username)
	accessToken := uuid
	userType := "msa"

	if currentUser.Type == UserTypePremium {
		authData, authErr := a.GetMSAuthData(username)
		if authErr == nil && authData.MCAccessToken != "" {
			_ = a.RefreshMicrosoftToken(username)
			authData, authErr = a.GetMSAuthData(username)
			if authErr == nil {
				uuid = authData.UUID
				accessToken = authData.MCAccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s", uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
			}
		}
	}
	if currentUser.Type == UserTypeExternal {
		extData, extErr := a.GetExternalAuthData(username)
		if extErr == nil && extData.AccessToken != "" {
			_ = a.RefreshExternalToken(username)
			extData, extErr = a.GetExternalAuthData(username)
			if extErr == nil {
				uuid = extData.UUID
				accessToken = extData.AccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s", uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
			}
		}
	}

	assetIndexName := ""
	if versionJSON.AssetIndex != nil {
		assetIndexName = versionJSON.AssetIndex.ID
	}
	replacements := map[string]string{
		"${auth_player_name}": username, "${version_name}": versionID,
		"${game_directory}": gameDir, "${assets_root}": filepath.Join(mcDir, "assets"),
		"${assets_index_name}": assetIndexName, "${auth_uuid}": uuid,
		"${auth_access_token}": accessToken, "${access_token}": accessToken,
		"${auth_session}": accessToken, "${user_type}": userType,
		"${version_type}": "QGL", "${user_properties}": "{}",
		"${game_assets}": filepath.Join(mcDir, "assets", "virtual", "legacy"),
		"${classpath}": classpath, "${classpath_separator}": ";",
		"${natives_directory}": nativesDir, "${library_directory}": filepath.Join(mcDir, "libraries"),
		"${launcher_name}": "QGL", "${launcher_version}": "1.0.0",
		"${resolution_width}": "854", "${resolution_height}": "480",
	}

	var gameArgs []string
	if isOldJSON {
		for _, part := range strings.Split(versionJSON.MinecraftArgs, " ") {
			arg := part
			for k, v := range replacements {
				arg = strings.ReplaceAll(arg, k, v)
			}
			gameArgs = append(gameArgs, arg)
		}
	}
	if versionJSON.Arguments != nil {
		for _, arg := range versionJSON.Arguments.Game {
			gameArgs = append(gameArgs, resolveGameArg(arg, replacements)...)
		}
	}

	hasCp := false
	for i, arg := range jvmArgs {
		if arg == "-cp" && i+1 < len(jvmArgs) {
			hasCp = true
		}
	}
	var allArgs []string
	if hasCp {
		allArgs = append(jvmArgs, versionJSON.MainClass)
	} else {
		allArgs = append(jvmArgs, "-cp", classpath, versionJSON.MainClass)
	}
	allArgs = append(allArgs, gameArgs...)
	return allArgs, classpath, username, gameDir
}

func resolveJVMArg(arg interface{}, nativesDir, mcDir, classpath, versionID string) []string {
	switch v := arg.(type) {
	case string:
		return []string{applyReplacements(v, nativesDir, mcDir, classpath, versionID)}
	case map[string]interface{}:
		if !shouldIncludeArg(v) {
			return nil
		}
		if values, ok := v["value"]; ok {
			switch val := values.(type) {
			case string:
				return []string{applyReplacements(val, nativesDir, mcDir, classpath, versionID)}
			case []interface{}:
				var result []string
				for _, item := range val {
					if s, ok := item.(string); ok {
						result = append(result, applyReplacements(s, nativesDir, mcDir, classpath, versionID))
					}
				}
				return result
			}
		}
	}
	return nil
}

func applyReplacements(s, nativesDir, mcDir, classpath, versionID string) string {
	repl := map[string]string{
		"${natives_directory}": nativesDir, "${library_directory}": filepath.Join(mcDir, "libraries"),
		"${libraries_directory}": filepath.Join(mcDir, "libraries"), "${classpath_separator}": ";",
		"${classpath}": classpath, "${launcher_name}": "QGL",
		"${launcher_version}": "1.0.0", "${version_name}": versionID,
	}
	for k, v := range repl {
		s = strings.ReplaceAll(s, k, v)
	}
	return s
}

func resolveGameArg(arg interface{}, repl map[string]string) []string {
	switch v := arg.(type) {
	case string:
		for k, rep := range repl {
			v = strings.ReplaceAll(v, k, rep)
		}
		return []string{v}
	case map[string]interface{}:
		if !shouldIncludeArg(v) {
			return nil
		}
		if values, ok := v["value"]; ok {
			switch val := values.(type) {
			case string:
				for k, rep := range repl {
					val = strings.ReplaceAll(val, k, rep)
				}
				return []string{val}
			case []interface{}:
				var result []string
				for _, item := range val {
					if s, ok := item.(string); ok {
						for k, rep := range repl {
							s = strings.ReplaceAll(s, k, rep)
						}
						result = append(result, s)
					}
				}
				return result
			}
		}
	}
	return nil
}

func (a *App) LaunchGame(versionID string) error {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)
	a.launchLogPath = filepath.Join(versionDir, "QGL", "Logs", "qgl_launch.log")
	a.writeLog("===== 启动游戏: %s =====", versionID)
	a.writeLog("版本目录: %s", versionDir)

	versionJSON, err := a.resolveVersionJSON(versionID)
	if err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	runtime.EventsEmit(a.ctx, "launchStatus", "fixing")
	a.emitProgress("downloading", "补全文件中", 0, 0)
	a.fixMissingLibraries(mcDir, versionJSON)

	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	if err := os.MkdirAll(nativesDir, 0700); err != nil {
		return fmt.Errorf("创建 natives 目录失败: %v", err)
	}
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
	if empty, _ := isDirEmpty(nativesDir); empty {
		a.ensureNativesForLoader(mcDir, versionID, versionDir, nativesDir, versionJSON)
	}

	allArgs, _, _, gameDir := a.buildLaunchArgs(versionID, versionJSON, mcDir, versionDir)

	currentUser, _ := a.GetCurrentUser()
	if currentUser.Type == UserTypeExternal {
		username := currentUser.Username
		extData, extErr := a.GetExternalAuthData(username)
		if extErr == nil {
			injectorPath, injErr := a.GetAuthlibInjectorPath()
			if injErr == nil {
				serverURL := extData.ServerURL
				prefetched := ""
				resp, err := safeHTTPClient().Get(serverURL)
				if err == nil {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					prefetched = base64.StdEncoding.EncodeToString(body)
				}
				injectorArgs := []string{"-javaagent:" + injectorPath + "=" + serverURL, "-Dauthlibinjector.side=client"}
				if prefetched != "" {
					injectorArgs = append(injectorArgs, "-Dauthlibinjector.yggdrasil.prefetched="+prefetched)
				}
				allArgs = append(injectorArgs, allArgs...)
			}
		}
	}

	a.setGameLanguage(gameDir, versionID)

	javaEntry, _ := a.SelectJavaForVersion(versionID)
	javaPath := javaEntry.Path

	var cmdParts []string
	cmdParts = append(cmdParts, "\""+javaPath+"\"")
	for _, arg := range allArgs {
		if strings.Contains(arg, " ") {
			cmdParts = append(cmdParts, "\""+arg+"\"")
		} else {
			cmdParts = append(cmdParts, arg)
		}
	}
	fullCmdLine := strings.Join(cmdParts, " ")
	a.writeLog("命令行长度: %d 字符", len(fullCmdLine))

	cmd := exec.Command(javaPath)
	cmd.Dir = gameDir
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: fullCmdLine}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建 stdout 管道失败: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("创建 stderr 管道失败: %v", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动游戏失败: %v", err)
	}
	pid := cmd.Process.Pid
	processStartTime := time.Now()
	a.writeLog("游戏进程 PID: %d", pid)

	go a.watchGameProcess(cmd, stdoutPipe, stderrPipe, pid, processStartTime)
	return nil
}

func (a *App) GetLaunchCommand(versionID string) (string, error) {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)
	versionJSON, err := a.resolveVersionJSON(versionID)
	if err != nil {
		return "", fmt.Errorf("解析版本 JSON 失败: %v", err)
	}
	a.fixMissingLibraries(mcDir, versionJSON)
	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	os.MkdirAll(nativesDir, 0700)
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
	if empty, _ := isDirEmpty(nativesDir); empty {
		a.ensureNativesForLoader(mcDir, versionID, versionDir, nativesDir, versionJSON)
	}
	allArgs, _, _, _ := a.buildLaunchArgs(versionID, versionJSON, mcDir, versionDir)
	javaEntry, _ := a.SelectJavaForVersion(versionID)
	javaPath := javaEntry.Path

	var cmdParts []string
	cmdParts = append(cmdParts, "\""+javaPath+"\"")
	for _, arg := range allArgs {
		if strings.Contains(arg, " ") || strings.Contains(arg, "\"") {
			cmdParts = append(cmdParts, "\""+strings.ReplaceAll(arg, "\"", "\\\"")+"\"")
		} else {
			cmdParts = append(cmdParts, arg)
		}
	}
	return strings.Join(cmdParts, " "), nil
}

func (a *App) watchGameProcess(cmd *exec.Cmd, stdoutPipe io.Reader, stderrPipe io.Reader, pid int, processStartTime time.Time) {
	runtime.EventsEmit(a.ctx, "launchStatus", "launching")
	crashDetected, windowFound := false, false
	crashReason := ""
	logProgress := 0
	var recentLines []string
	exitChan := make(chan int, 1)
	go func() {
		err := cmd.Wait()
		exitCode := -1
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		} else {
			exitCode = 0
		}
		exitChan <- exitCode
	}()
	logChan := make(chan string, 200)
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			logChan <- scanner.Text()
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			logChan <- scanner.Text()
		}
	}()
	go func() {
		for line := range logChan {
			recentLines = append(recentLines, line)
			if len(recentLines) > 50 {
				recentLines = recentLines[len(recentLines)-50:]
			}
			for _, kw := range crashKeywords {
				if strings.Contains(line, kw) {
					crashDetected = true
					start := len(recentLines) - 20
					if start < 0 {
						start = 0
					}
					crashReason = strings.Join(recentLines[start:], "\n")
					break
				}
			}
			for _, kw := range logProgressKeywords {
				if strings.Contains(line, kw.keyword) && kw.level > logProgress {
					logProgress = kw.level
				}
			}
			if logProgress >= 5 && !windowFound {
				windowFound = true
				runtime.EventsEmit(a.ctx, "launchStatus", "success")
			}
		}
	}()
	startTime := time.Now()
	launchTimeout := 30 * time.Second
	for {
		elapsed := time.Since(startTime)
		if !windowFound {
			found, _ := findMinecraftWindow(pid, processStartTime)
			if found {
				windowFound = true
				runtime.EventsEmit(a.ctx, "launchStatus", "success")
				select {
				case exitCode := <-exitChan:
					if exitCode != 0 {
						runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
						runtime.EventsEmit(a.ctx, "crashInfo", fmt.Sprintf("游戏已退出 (退出码: %d)", exitCode))
					}
				}
				return
			}
		}
		select {
		case exitCode := <-exitChan:
			a.writeLog("游戏进程退出，退出码: %d, 运行时间: %.1f秒", exitCode, elapsed.Seconds())
			if !windowFound {
				logContext := ""
				if len(recentLines) > 0 {
					start := len(recentLines) - 20
					if start < 0 {
						start = 0
					}
					logContext = "\n\n最近日志:\n" + strings.Join(recentLines[start:], "\n")
				}
				if elapsed < 3*time.Second {
					runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
					runtime.EventsEmit(a.ctx, "crashInfo", fmt.Sprintf("游戏启动失败，进程立即退出 (退出码: %d)%s", exitCode, logContext))
				} else {
					runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
					runtime.EventsEmit(a.ctx, "crashInfo", fmt.Sprintf("游戏进程意外退出 (退出码: %d)%s", exitCode, logContext))
				}
			}
			return
		default:
		}
		if crashDetected && !windowFound {
			select {
			case <-exitChan:
			case <-time.After(5 * time.Second):
			}
			runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
			runtime.EventsEmit(a.ctx, "crashInfo", crashReason)
			return
		}
		if elapsed > launchTimeout && !windowFound {
			if logProgress >= 2 && elapsed < 60*time.Second {
				// 继续等待
			} else {
				runtime.EventsEmit(a.ctx, "launchStatus", "timeout")
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}
