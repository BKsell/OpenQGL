package main

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"unicode"
	"unsafe"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ===== Win32 API 用于窗口检测 =====

var (
	user32DLL           = syscall.NewLazyDLL("user32.dll")
	kernel32DLL         = syscall.NewLazyDLL("kernel32.dll")
	procEnumWindows     = user32DLL.NewProc("EnumWindows")
	procGetClassName    = user32DLL.NewProc("GetClassNameA")
	procGetWindowText   = user32DLL.NewProc("GetWindowTextA")
	procGetWindowPID    = user32DLL.NewProc("GetWindowThreadProcessId")
	procOpenProcess     = kernel32DLL.NewProc("OpenProcess")
	procGetProcessTimes = kernel32DLL.NewProc("GetProcessTimes")
	procCloseHandle     = kernel32DLL.NewProc("CloseHandle")
)

// 下载体积上限，防止恶意服务器用无限流把磁盘/内存写爆。
const (
	maxJavaInstallerBytes    = 500 << 20 // 500 MiB，JRE 安装包实际 ~40-70 MiB
	maxAuthlibPrefetchBytes  = 1 << 20  // 1 MiB，authlibinjector 抓取的皮肤站首页
	maxVersionManifestBytes   = 8 << 20  // 8 MiB，版本清单/资产索引 JSON
)

// MCVersion 表示一个 Minecraft 版本
type MCVersion struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	ReleaseTime string `json:"releaseTime"`
}

// VersionManifest 版本清单
type VersionManifest struct {
	Latest struct {
		Release  string `json:"release"`
		Snapshot string `json:"snapshot"`
	} `json:"latest"`
	Versions []MCVersionInfo `json:"versions"`
}

// MCVersionInfo 版本信息
type MCVersionInfo struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	ReleaseTime string `json:"releaseTime"`
}

// DownloadProgress 下载进度
type DownloadProgress struct {
	TotalBytes      int64   `json:"totalBytes"`
	DownloadedBytes int64   `json:"downloadedBytes"`
	Percentage      float64 `json:"percentage"`
	CurrentFile     string  `json:"currentFile"`
	Status          string  `json:"status"`
}

// DownloadItem 下载列表项
type DownloadItem struct {
	ID             string  `json:"id"`
	URL            string  `json:"url"`
	CustomName     string  `json:"customName"`
	Type           string  `json:"type"`
	ItemType       string  `json:"itemType"`
	JavaMajor      int     `json:"javaMajor"`
	SavePath       string  `json:"savePath"`
	LoaderName     string  `json:"loaderName"`
	LoaderVersion  string  `json:"loaderVersion"`
	OptiFineType   string  `json:"optifineType"`
	OptiFinePatch  string  `json:"optifinePatch"`
	Status         string  `json:"status"`
	Progress       float64 `json:"progress"`
	ErrorMsg       string  `json:"errorMsg"`
}

// 版本 JSON 相关结构体

type VersionJSON struct {
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	MainClass     string            `json:"mainClass"`
	MinecraftArgs string            `json:"minecraftArguments"`
	Arguments     *ArgumentsObj     `json:"arguments"`
	Libraries     []Library         `json:"libraries"`
	Downloads     *VersionDownloads `json:"downloads"`
	AssetIndex    *AssetIndexRef    `json:"assetIndex"`
	ReleaseTime   string            `json:"releaseTime"`
	InheritsFrom  string            `json:"inheritsFrom"`
	Jar           string            `json:"jar"`
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

// InstalledVersionInfo 安装版本的信息
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

// maxUnverifiedDownloadBytes 未做哈希校验的下载上限 4 GiB。
// 走这个函数的库 / 安装器体积都远小于此值；正常数据永远碰不到，
// 只有被劫持的镜像持续灌数据炸磁盘时才会触发中止并删除残文件。
const maxUnverifiedDownloadBytes int64 = 4 << 30

// maxMetadataJSONBytes 版本 JSON / 资产索引这类元数据 JSON 的上限。
// 官方文件只有几百 KB ~ 数 MB；它们走通用下载（4 GiB）落地后又被
// os.ReadFile 整体读进内存，被劫持镜像灌一个 GB 级"json"会直接 OOM。
// 单独收窄到 16 MiB，正常数据永远碰不到。
const maxMetadataJSONBytes int64 = 16 << 20

// maxAssetObjectBytes 单个 assets/objects 资源对象上限。
// 内容寻址（路径/URL 即 SHA1），普通贴图/语言文件几 KB，音乐较大也远小于此。
const maxAssetObjectBytes int64 = 256 << 20

var errDownloadTooLarge = errors.New("下载体积超过安全上限")

// cappedReader 读到第 max+1 个字节时返回 errDownloadTooLarge，
// 配合调用方删除残文件，避免恶意端点靠超大响应撑爆磁盘。
type cappedReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, errDownloadTooLarge
	}
	return n, err
}

// readBoundedFile 把本地文件读入内存，但先用 stat 体积、再用 LimitReader+1
// 双保险封顶，防止把磁盘上被塞成 GB 级的"元数据 JSON"整体读进内存导致 OOM。
func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil && info.Size() > maxBytes {
		return nil, fmt.Errorf("文件 %s 体积 %d 超过元数据上限 %d", path, info.Size(), maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("文件 %s 超过元数据上限 %d", path, maxBytes)
	}
	return data, nil
}

// downloadContext 返回一个与“下载列表取消信号”绑定的 context。
// 之前 CancelDownloadList 只能在两个文件之间跳出循环，正在传输的大文件
// 仍要等下完才停；把请求挂到这个 context 上后，取消会立刻中断进行中的 HTTP 读取。
// 非下载列表场景（如启动时补全文件）没有取消信号，返回普通 Background context。
func (a *App) downloadContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	a.downloadMutex.Lock()
	ch := a.downloadCancel
	a.downloadMutex.Unlock()
	if ch == nil {
		return ctx, cancel
	}
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (a *App) downloadFile(url string, destPath string, reportProgress bool) error {
	return a.downloadFileBounded(url, destPath, reportProgress, maxUnverifiedDownloadBytes)
}

// downloadFileBounded 与 downloadFile 相同，但允许调用方按文件类型指定体积上限，
// 让版本 JSON / 资产索引等小元数据不必套用 4 GiB 的宽松上限。
//
// 实际的 HTTP 请求 / 体积双校验 / 流式 sha256 / 原子落盘 / 503 退避重试统一走
// streamVerifiedDownload：这里只保留"已存在跳过""进度上报到前端""错误归一化"
// 三层 App 语义，避免各下载点各自手写请求体。
func (a *App) downloadFileBounded(url string, destPath string, reportProgress bool, maxBytes int64) error {
	if !isHTTPSURL(url) {
		return fmt.Errorf("拒绝不安全的下载 URL（非 HTTPS）: %s", url)
	}
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("创建目录失败 %s: %v", dir, err)
	}
	if info, err := os.Stat(destPath); err == nil && info.Size() > 0 {
		return nil
	}
	ctx, cancelReq := a.downloadContext()
	defer cancelReq()
	opts := secureDownloadOptions{
		MaxBytes:  maxBytes,
		Attempts:  3,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Client:    safeHTTPClient(),
	}
	if reportProgress {
		opts.Progress = func(received, total int64) {
			a.emitProgress("downloading", filepath.Base(destPath), received, total)
		}
	}
	if _, err := streamVerifiedDownload(ctx, url, destPath, opts); err != nil {
		if errors.Is(err, errSecureDownloadTooLarge) {
			return fmt.Errorf("下载失败 %s: %w", url, errDownloadTooLarge)
		}
		return fmt.Errorf("下载失败 %s: %v", url, err)
	}
	return nil
}

// downloadVerifiedFile 下载并校验官方 SHA1；缓存命中走侧车摘要链
// （UMFS -> SHA512 -> SHA1）快速复用，新下载落盘则以官方 SHA1 为唯一信任锚
// 校验通过后再补写 UMFS/SHA512 侧车；校验失败删除重下一次。
func (a *App) downloadVerifiedFile(url string, destPath string, expectedSHA1 string, reportProgress bool) error {
	if expectedSHA1 == "" {
		return a.downloadFile(url, destPath, reportProgress)
	}
	expected := strings.ToLower(strings.TrimSpace(expectedSHA1))
	if info, err := os.Stat(destPath); err == nil && info.Size() > 0 && a.verifyCachedFile(destPath, expected) {
		return nil
	}
	os.Remove(destPath)
	removeCachedFileMeta(destPath)
	if err := a.downloadFile(url, destPath, reportProgress); err != nil {
		return err
	}
	// 外部协议摘要（Mojang SHA1）保持原算法，是首次下载唯一的权威校验。
	if !a.checkFileHash(destPath, expected) {
		os.Remove(destPath)
		removeCachedFileMeta(destPath)
		return fmt.Errorf("SHA1 校验失败: %s", destPath)
	}
	// 官方 SHA1 已通过：本地缓存摘要用 bool-hybrid-array 生态的 UMFS 优先记录。
	if err := a.saveCachedFileMeta(destPath, expected); err != nil {
		a.writeLog("缓存元数据写入失败（不影响完整性）: %s: %v", destPath, err)
	}
	return nil
}

// GetVersionManifest 获取版本清单
func (a *App) GetVersionManifest() ([]MCVersion, error) {
	urls := []string{
		"https://bmclapi2.bangbang93.com/mc/game/version_manifest_v2.json",
		"https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
	}
	var manifest VersionManifest
	opts := jsonFetchOptions{
		MaxBytes:        maxVersionManifestBytes,
		Attempts:        2,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Client:          safeHTTPClient(),
		AllowMediaTypes: []string{"application/json"},
		SourceLabel:     "版本清单",
	}
	if err := fetchJSONFromMirrors(context.Background(), urls, &manifest, opts); err != nil {
		return nil, fmt.Errorf("获取版本清单失败: %v", err)
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
	jsonText, _ := readBoundedFile(jsonPath, maxMetadataJSONBytes)
	loader := ""
	if strings.Contains(string(jsonText), "net.fabricmc:fabric-loader") {
		loader = "fabric"
	} else if strings.Contains(string(jsonText), "org.quiltmc:quilt-loader") {
		loader = "quilt"
	} else if strings.Contains(string(jsonText), "net.neoforged") {
		loader = "neoforge"
	} else if strings.Contains(string(jsonText), "minecraftforge") && !strings.Contains(string(jsonText), "net.neoforged") {
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
	customName = sanitizeVersionName(customName)
	if customName == "" {
		return fmt.Errorf("版本名称无效")
	}
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
		if parseErr != nil || parsedURL.Scheme != "https" {
			return fmt.Errorf("Java 下载页面必须使用 HTTPS: %s", url)
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
	if strings.ContainsAny(target.FileName, `/\\`) || strings.HasPrefix(target.FileName, `..`) {
		return fmt.Errorf(`不安全的 Java 安装文件名: %s`, target.FileName)
	}
	destPath := filepath.Join(tempDir, target.FileName)
	// %TEMP% 对同用户其它进程可写：不能看到同名文件就直接执行，否则恶意程序
	// 预先放一个同名 msi/exe 就会被我们拉起。先清掉残留（符号链接只删链接
	// 本身），本次下载的内容才是即将被校验执行的内容。发现残留本身值得审计：
	// 正常首次下载时这里应该什么都没有。
	if pre, statErr := os.Lstat(destPath); statErr == nil {
		kind := "普通文件"
		if pre.Mode()&os.ModeSymlink != 0 {
			kind = "符号链接"
		} else if !pre.Mode().IsRegular() {
			kind = "特殊文件"
		}
		recordSecurityEvent(auditCategoryInstaller, auditSeverityCritical, auditActionBlocked,
			"minecraft", "TEMP 中发现预置同名安装包("+kind+")，拒绝执行并清除: "+destPath)
	}
	if err := removeStaleInstaller(destPath); err != nil {
		return fmt.Errorf("清理旧安装包失败: %v", err)
	}
	a.emitProgress("downloading", target.FileName, 0, 0)
	ctx, cancelReq := a.downloadContext()
	defer cancelReq()
	// 安装包与普通游戏文件走同一条安全通道：HTTPS 强制、声明/实际体积双校验、
	// 临时文件流式落盘 + fsync + 原子 rename、503/网络抖动指数退避重试，
	// 失败不会在 TEMP 留半截安装包。安装包紧接着要被执行，落盘后必须补
	// Mark of the Web（ZoneId=3 Internet），让 SmartScreen 按互联网来源处置，
	// 而不是把刚下载的文件当成本机原生文件。
	opts := secureDownloadOptions{
		MaxBytes:      maxJavaInstallerBytes,
		Attempts:      3,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Client:        safeHTTPClient(),
		MarkWebOrigin: true,
		Progress: func(received, total int64) {
			a.emitProgress("downloading", target.FileName, received, total)
		},
	}
	if _, err := streamVerifiedDownload(ctx, url, destPath, opts); err != nil {
		if errors.Is(err, errSecureDownloadTooLarge) {
			return fmt.Errorf("下载失败 %s: %w", url, errDownloadTooLarge)
		}
		return fmt.Errorf("下载失败: %v", err)
	}
	return runInstaller(destPath, target.IsMSI)
}

func runInstaller(filePath string, isMSI bool) error {
	if err := validateInstallerPackage(filePath, isMSI); err != nil {
		recordSecurityEvent(auditCategoryInstaller, auditSeverityCritical, auditActionBlocked,
			"minecraft", "安装包执行前校验失败: "+err.Error())
		return err
	}
	if isMSI {
		cmd := exec.Command("msiexec", "/i", filePath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Start()
	}
	cmd := exec.Command("explorer", filePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

func (a *App) DownloadVersion(versionID string, versionURL string, customName string) error {
	mcDir := a.getMinecraftDir()
	customName = sanitizeVersionName(customName)
	if customName == "" {
		return fmt.Errorf("无效的版本名称")
	}
	versionDir := filepath.Join(mcDir, "versions", customName)
	if err := os.MkdirAll(versionDir, 0700); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}
	a.emitProgress("downloading", customName+".json", 0, 0)
	jsonURL := replaceWithBMCLAPI(versionURL)
	jsonPath := filepath.Join(versionDir, customName+".json")
	if err := a.downloadFileBounded(jsonURL, jsonPath, false, maxMetadataJSONBytes); err != nil {
		return fmt.Errorf("下载版本 JSON 失败: %v", err)
	}
	jsonData, err := readBoundedFile(jsonPath, maxMetadataJSONBytes)
	if err != nil {
		return fmt.Errorf("读取版本 JSON 失败: %v", err)
	}
	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}
	// 先把清单内 URL 归一化为真正发起请求时的地址（BMCLAPI 重写是确定性、受信任的），
	// 白名单审计必须针对“实际抓取主机”，否则会误杀走 launcher.mojang.com 的老清单，
	// 也避免攻击者靠“审计看 A、实际请求 B”的差异绕过。
	if versionJSON.Downloads != nil {
		if versionJSON.Downloads.Client != nil {
			versionJSON.Downloads.Client.URL = replaceWithBMCLAPI(versionJSON.Downloads.Client.URL)
		}
		if versionJSON.Downloads.Server != nil {
			versionJSON.Downloads.Server.URL = replaceWithBMCLAPI(versionJSON.Downloads.Server.URL)
		}
	}
	for i := range versionJSON.Libraries {
		dl := versionJSON.Libraries[i].Downloads
		if dl == nil {
			continue
		}
		if dl.Artifact != nil {
			dl.Artifact.URL = replaceWithBMCLAPI(dl.Artifact.URL)
		}
		for _, art := range dl.Classifiers {
			if art != nil {
				art.URL = replaceWithBMCLAPI(art.URL)
			}
		}
	}
	if versionJSON.AssetIndex != nil {
		versionJSON.AssetIndex.URL = replaceWithBMCLAPI(versionJSON.AssetIndex.URL)
	}
	// 版本 JSON 来自可由前端指定的第三方 versionURL，client / library / native 的
	// url/path/sha1 全部不受信任：下载主机必须落在官方 / 镜像白名单，可执行产物必须
	// 带合法 SHA1，库路径必须是严格 Maven 相对路径，资源索引 ID 必须是单段安全名。
	// critical 一律拒绝下载（防止攻击者把 jar 指向自己的服务器落进 classpath）。
	manifestFindings := auditVersionManifest(&versionJSON)
	for i := range manifestFindings {
		f := &manifestFindings[i]
		if f.Severity == manifestCritical {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityCritical, auditActionBlocked,
				"version-manifest", f.Field+": "+f.Detail)
		} else {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionDetected,
				"version-manifest", f.Field+": "+f.Detail)
		}
	}
	if manifestHasCritical(manifestFindings) {
		return manifestCriticalError(manifestFindings)
	}
	if versionJSON.Downloads != nil && versionJSON.Downloads.Client != nil {
		client := versionJSON.Downloads.Client
		clientURL := replaceWithBMCLAPI(client.URL)
		jarPath := filepath.Join(versionDir, customName+".jar")
		a.emitProgress("downloading", customName+".jar", 0, client.Size)
		if err := a.downloadVerifiedFile(clientURL, jarPath, client.SHA1, true); err != nil {
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
			// Zip Slip 防护：库路径走严格 Maven 相对路径白名单（拒盘符/反斜杠/冒号）
			safePath := SafeMavenRelPath(artifact.Path)
			if safePath == "" {
				fmt.Printf("跳过不安全的库路径: %s\n", artifact.Path)
				continue
			}
			libPath := filepath.Join(mcDir, "libraries", filepath.FromSlash(safePath))
			libURL := replaceWithBMCLAPI(artifact.URL)
			a.emitProgress("downloading", filepath.Base(artifact.Path), 0, artifact.Size)
			if err := a.downloadVerifiedFile(libURL, libPath, artifact.SHA1, false); err != nil {
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
			// Zip Slip 防护：native 路径走严格 Maven 相对路径白名单
			safeClassPath := SafeMavenRelPath(classifier.Path)
			if safeClassPath == "" {
				fmt.Printf("跳过不安全的 native 路径: %s\n", classifier.Path)
				continue
			}
			nativePath := filepath.Join(mcDir, "libraries", filepath.FromSlash(safeClassPath))
			nativeURL := replaceWithBMCLAPI(classifier.URL)
			a.emitProgress("downloading", filepath.Base(classifier.Path), 0, classifier.Size)
			if err := a.downloadVerifiedFile(nativeURL, nativePath, classifier.SHA1, false); err != nil {
				fmt.Printf("下载 native 失败: %s, %v\n", classifier.Path, err)
			}
		}
	}
	if versionJSON.AssetIndex != nil {
		assetIndexRef := versionJSON.AssetIndex
		// 资产索引 ID 来自外部版本 JSON，会直接拼进文件路径，必须强制为
		// 单段安全名，防止 "1.21/../../x.json" 之类路径穿越或落到非预期位置。
		safeIndexID := SafeSimpleName(assetIndexRef.ID)
		if safeIndexID == "" {
			return fmt.Errorf("资产索引 ID 不安全，拒绝继续: %q", assetIndexRef.ID)
		}
		assetIndexDir := filepath.Join(mcDir, "assets", "indexes")
		assetIndexPath := filepath.Join(assetIndexDir, safeIndexID+".json")
		assetIndexURL := replaceWithBMCLAPI(assetIndexRef.URL)
		a.emitProgress("downloading", "资源索引", 0, 0)
		if err := a.downloadFileBounded(assetIndexURL, assetIndexPath, false, maxMetadataJSONBytes); err != nil {
			fmt.Printf("下载资源索引失败: %v\n", err)
		} else {
			assetIndexData, err := readBoundedFile(assetIndexPath, maxMetadataJSONBytes)
			if err == nil {
				var assetIndex AssetIndex
				if json.Unmarshal(assetIndexData, &assetIndex) == nil {
					totalAssets := len(assetIndex.Objects)
					count := 0
					for name, obj := range assetIndex.Objects {
						count++
						// 对象哈希既拼下载 URL 也拼本地 objects/xx/<40hex> 路径，
						// 且会做 hash[:2] 切片：必须严格是 40 位小写十六进制，
						// 否则既可能路径穿越，也会因长度不足直接 panic 崩溃。
						if !IsLowerHex(obj.Hash, 40) {
							a.writeLog("跳过哈希非法的资源 %s: %q", name, obj.Hash)
							continue
						}
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

// checkFileHash 校验文件完整性（SHA1，用于验证 Mojang manifest 提供的哈希）
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
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	actualHash := fmt.Sprintf("%x", h.Sum(nil))
	return actualHash == expectedSHA1
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

func (a *App) downloadFromMirrors(urls []string, destPath string, maxBytes int64) bool {
	for attempt, url := range urls {
		os.Remove(destPath)
		os.MkdirAll(filepath.Dir(destPath), 0700)
		if err := a.downloadFileBounded(url, destPath, false, maxBytes); err != nil {
			a.writeLog("下载失败 [%s]: %v", url, err)
			// 切下一个镜像前做一次可中断的退避（mt_xor25 抖动 ±25%），
			// 既避免失败后瞬间重试压垮镜像，也让多实例不会同步重试；取消下载立即返回。
			if attempt+1 < len(urls) {
				base := time.Duration(attempt+1) * 500 * time.Millisecond
				if !a.sleepOrCancel(mtXor25Jitter(base)) {
					return false
				}
			}
			continue
		}
		return true
	}
	return false
}

// sleepOrCancel 休眠 d，期间若下载列表被取消则立即返回 false；正常到点返回 true。
func (a *App) sleepOrCancel(d time.Duration) bool {
	a.downloadMutex.Lock()
	ch := a.downloadCancel
	a.downloadMutex.Unlock()
	if ch == nil {
		time.Sleep(d)
		return true
	}
	select {
	case <-ch:
		return false
	case <-time.After(d):
		return true
	}
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
	if a.downloadFromMirrors(urls, assetIndexPath, maxMetadataJSONBytes) {
		a.writeLog("资源索引文件下载完成: %s", versionJSON.AssetIndex.ID)
		a.fixMissingAssets(mcDir, assetIndexPath)
	} else {
		a.writeLog("资源索引文件下载失败: %s", versionJSON.AssetIndex.ID)
	}
}

func (a *App) fixMissingAssets(mcDir string, assetIndexPath string) {
	data, err := readBoundedFile(assetIndexPath, maxMetadataJSONBytes)
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
		if a.downloadFromMirrors(urls, objPath, maxAssetObjectBytes) {
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

// 单个 / 全部 native 条目解压后的体积上限。
// 正常的 .dll / .so / .jnilib 远小于这些值，上限只在“异常压缩包 / zip 炸弹”时触发，
// 避免一个恶意 natives jar 借超大条目或高压缩比把磁盘写满。
const (
	maxNativeEntryBytes int64 = 256 << 20 // 256 MiB / 单个 native
	maxNativeTotalBytes int64 = 2 << 30   // 2 GiB / 单次解压总量
)

func extractNatives(jarPath string, destDir string) (int, error) {
	return extractNativesWithLimits(jarPath, destDir, maxNativeEntryBytes, maxNativeTotalBytes)
}

// extractNativesWithLimits 是真正的解压内核，单文件 / 总量上限由调用方传入，
// 既让生产路径用固定安全常量，也便于用小阈值对体积边界做轻量单测（不必造几百 MiB 数据）。
func extractNativesWithLimits(jarPath string, destDir string, entryMax, totalMax int64) (int, error) {
	r, err := zip.OpenReader(jarPath)
	if err != nil {
		os.Remove(jarPath)
		return 0, fmt.Errorf("打开 Natives 文件失败（文件可能已损坏）: %s", jarPath)
	}
	defer r.Close()
	count := 0
	var total int64
	for _, f := range r.File {
		if f.FileInfo().IsDir() || strings.HasPrefix(f.Name, "META-INF/") {
			continue
		}
		// 符号链接 / 设备等特殊条目绝不落地，即便伪装成 .dll 后缀。
		if f.Mode()&(os.ModeSymlink|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0 {
			continue
		}
		lowerName := strings.ToLower(f.Name)
		if !strings.HasSuffix(lowerName, ".dll") && !strings.HasSuffix(lowerName, ".jnilib") && !strings.HasSuffix(lowerName, ".so") {
			continue
		}
		// zip 头里声明的解压体积可先廉价挡一刀；真正的边界仍靠 LimitReader，不信任该值。
		if f.UncompressedSize64 > uint64(entryMax) {
			return count, fmt.Errorf("native 条目 %s 声明体积超过单文件上限", f.Name)
		}
		if total >= totalMax || total+int64(f.UncompressedSize64) > totalMax {
			return count, fmt.Errorf("native 解压总量超过 %d 字节上限，疑似 zip 炸弹", totalMax)
		}
		fileName := filepath.Base(f.Name)
		destPath := filepath.Join(destDir, fileName)
		if info, err := os.Stat(destPath); err == nil && info.Size() == f.FileInfo().Size() {
			count++
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		if err := os.MkdirAll(destDir, 0700); err != nil {
			rc.Close()
			return count, fmt.Errorf("创建 natives 目录失败: %v", err)
		}
		// 先写到同目录临时文件，完整通过体积校验后再原子替换，避免留下半截大文件。
		tmp, err := os.CreateTemp(destDir, ".native-*.tmp")
		if err != nil {
			rc.Close()
			continue
		}
		tmpName := tmp.Name()
		limited := io.LimitReader(rc, entryMax+1)
		n, copyErr := io.Copy(tmp, limited)
		tmp.Close()
		rc.Close()
		if copyErr != nil {
			os.Remove(tmpName)
			continue
		}
		if n > entryMax || total+n > totalMax {
			os.Remove(tmpName)
			if n > entryMax {
				return count, fmt.Errorf("native 条目 %s 解压后超过单文件上限", fileName)
			}
			return count, fmt.Errorf("native 解压总量超过 %d 字节上限，疑似 zip 炸弹", totalMax)
		}
		if err := os.Chmod(tmpName, 0600); err != nil {
			os.Remove(tmpName)
			continue
		}
		if err := os.Rename(tmpName, destPath); err != nil {
			os.Remove(tmpName)
			continue
		}
		total += n
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
		// 与下载阶段一致，这里必须再次校验 classifier.Path：版本 JSON 来自镜像
		// 站（不可信），而本函数也会被非 DownloadVersion 的其它启动流程调用。
		safeClassifierPath := isSafeRelPath(classifier.Path)
		if safeClassifierPath == "" {
			a.writeLog("跳过不安全的 native jar 路径: %s", classifier.Path)
			continue
		}
		nativeJarPath := filepath.Join(mcDir, "libraries", safeClassifierPath)
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
	if rawParent := strings.TrimSpace(versionJSON.InheritsFrom); rawParent != "" {
		parentName := safeVersionName(rawParent)
		if parentName != "" {
			parentNativesDir := filepath.Join(mcDir, "versions", parentName, parentName+"-natives")
			if entries, err := os.ReadDir(parentNativesDir); err == nil && len(entries) > 0 {
				fmt.Printf("从父版本复制 natives: %s -> %s\n", parentNativesDir, nativesDir)
				copyDirContents(parentNativesDir, nativesDir)
				return
			}
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
				copyDirContents(candidateNatives, nativesDir)
				return
			}
		}
	}
	fmt.Printf("尝试重新解压 natives 到: %s\n", nativesDir)
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
}

// copyDirContents 只复制 srcDir 顶层的普通文件到 dstDir（不递归）。
// 显式跳过符号链接 / 特殊文件，并对单文件与总量设上限：源目录是各版本 natives，
// 正常只含体积有限的 .dll/.so；跳过链接可避免把链接目标（可能指向目录外敏感文件）
// 以普通文件形式带进运行目录。
const maxCopyDirEntryBytes int64 = 256 << 20

func copyDirContents(srcDir string, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// ReadDir 不跟随链接：任何非常规文件（符号链接 / 设备 / 管道等）一律跳过。
		if entry.Type()&os.ModeType != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Size() > maxCopyDirEntryBytes || total+info.Size() > maxNativeTotalBytes {
			continue
		}
		data, err := os.ReadFile(filepath.Join(srcDir, entry.Name()))
		if err != nil {
			continue
		}
		if int64(len(data)) > maxCopyDirEntryBytes || total+int64(len(data)) > maxNativeTotalBytes {
			continue
		}
		if err := os.WriteFile(filepath.Join(dstDir, entry.Name()), data, 0600); err != nil {
			continue
		}
		total += int64(len(data))
	}
	return nil
}

// generateOfflineUUID 使用 UMFS 哈希（bool-hybrid-array 生态）
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

// isValidMavenToken 校验 Maven 坐标中的单个片段（groupId 段 / artifactId /
// version / classifier）。版本 JSON 来自镜像站，属于不可信输入：只要片段里出现
// 路径分隔符、盘符、".." 或 Maven 坐标不允许的空白 / 控制字符，就判为非法，
// 防止恶意坐标经 mavenNameToPath 拼出逃逸 libraries 目录的路径。
func isValidMavenToken(token string) bool {
	if token == "" || token == "." || token == ".." {
		return false
	}
	if len(token) > 255 {
		return false
	}
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			// 字母数字
		case strings.ContainsRune("-_.@+", r):
			// Maven 常见合法字符
		default:
			return false
		}
	}
	return true
}

func mavenNameToPath(name string, libsDir string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}
	// 坐标的每一段都必须是干净的 Maven token；groupId 的每个 "." 分段也要
	// 单独校验，否则 "..\.." 之类会在 ReplaceAll 之后变成路径穿越。
	groupParts := strings.Split(parts[0], ".")
	for _, seg := range groupParts {
		if !isValidMavenToken(seg) {
			return ""
		}
	}
	artifact, version := parts[1], parts[2]
	if !isValidMavenToken(artifact) || !isValidMavenToken(version) {
		return ""
	}
	classifier := ""
	if len(parts) >= 4 {
		if !isValidMavenToken(parts[3]) {
			return ""
		}
		classifier = "-" + parts[3]
	}
	group := strings.Join(groupParts, string(os.PathSeparator))
	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)
	rel := filepath.Join(group, artifact, version, fileName)
	// 拼好后再用统一的相对路径校验兜底，确保结果一定在 libraries 内。
	if isSafeRelPath(rel) == "" {
		return ""
	}
	return filepath.Join(libsDir, rel)
}

func (a *App) resolveVersionJSON(versionID string) (*VersionJSON, error) {
	// 入口版本 ID 同样来自外部（版本目录扫描 / 前端），必须先收敛成单段安全名，
	// 避免把 "../../x" 之类直接拼进 versions/<id>/<id>.json 造成路径穿越。
	// 版本名允许空格 / 中文等，只拦分隔符、盘符与控制符（见 safeVersionName）。
	safeID := safeVersionName(versionID)
	if safeID == "" {
		return nil, fmt.Errorf("版本 ID 不是合法的单段名称，拒绝解析: %q", versionID)
	}
	return a.resolveVersionJSONSafe(safeID, 0, map[string]bool{})
}

// resolveVersionJSONSafe 在继承深度 / 成环检测下递归解析版本 JSON。
func (a *App) resolveVersionJSONSafe(versionID string, depth int, seen map[string]bool) (*VersionJSON, error) {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)
	jsonPath := filepath.Join(versionDir, versionID+".json")
	if _, err := os.Stat(jsonPath); err != nil {
		jsonFiles, _ := filepath.Glob(filepath.Join(versionDir, "*.json"))
		if len(jsonFiles) > 0 {
			jsonPath = jsonFiles[0]
		}
	}
	jsonData, err := readBoundedFile(jsonPath, maxMetadataJSONBytes)
	if err != nil {
		return nil, fmt.Errorf("未找到或无法读取版本 JSON: %s (%v)", versionDir, err)
	}
	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return nil, fmt.Errorf("解析版本 JSON 失败: %v", err)
	}
	if rawParent := strings.TrimSpace(versionJSON.InheritsFrom); rawParent != "" {
		parentID, perr := validateInheritStep(rawParent, depth, seen)
		if perr != nil {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityCritical, auditActionBlocked,
				"version-manifest", "inheritsFrom: "+perr.Error())
			return nil, perr
		}
		seen[versionID] = true
		parentJSON, perr := a.resolveVersionJSONSafe(parentID, depth+1, seen)
		if perr != nil {
			fmt.Printf("解析父版本 JSON 失败: %v（继续使用当前版本信息）\n", perr)
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
			safePath := isSafeRelPath(lib.Downloads.Artifact.Path)
			if safePath == "" {
				continue
			}
			libPath = filepath.Join(libsDir, safePath)
		} else if lib.JarPath != "" {
			// lib.JarPath 是镜像 JSON 直接给的相对路径，必须校验，
			// 否则恶意条目可以把 libraries 之外的任意 jar 塞进启动 classpath。
			safeJarPath := isSafeRelPath(lib.JarPath)
			if safeJarPath == "" {
				continue
			}
			libPath = filepath.Join(libsDir, safeJarPath)
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
	// Jar / InheritsFrom 来自外部版本 JSON，会拼进 versions/<name>/<name>.jar，
	// 必须逐个收敛成单段安全名；三者都非法时跳过该 classpath 条目而不是拼出穿越路径。
	jarName := ""
	for _, c := range []string{versionJSON.Jar, versionJSON.InheritsFrom, versionID} {
		if s := safeVersionName(c); s != "" {
			jarName = s
			break
		}
	}
	if jarName != "" {
		versionJar := filepath.Join(mcDir, "versions", jarName, jarName+".jar")
		if _, err := os.Stat(versionJar); err != nil {
			if self := safeVersionName(versionID); self != "" {
				altJar := filepath.Join(mcDir, "versions", self, self+".jar")
				if _, err2 := os.Stat(altJar); err2 == nil {
					versionJar = altJar
				}
			}
		}
		entries = append(entries, versionJar)
	}
	return entries
}

// sanitizeLaunchUsername 清洗进入游戏命令行参数的用户名。
// 老版本 version JSON 的 MinecraftArgs 是按空格切分的字符串，
// 用户名里只要含空格/制表符/控制字符，就能在 ${auth_player_name} 处
// 注入任意额外游戏参数（参数注入）。这里剔除空白与控制字符、按 16 个
// rune 截断（Minecraft 用户名上限），清洗后为空则回退 Player。
// 正版用户名本身只会含字母数字下划线，此清洗不影响正常用户。
func sanitizeLaunchUsername(raw string) string {
	var b strings.Builder
	count := 0
	for _, r := range raw {
		if count >= 16 {
			break
		}
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
		count++
	}
	name := b.String()
	if name == "" {
		return "Player"
	}
	return name
}

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
	if !a.isVersionIsolation() {
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
		}
		if versionJSON.Arguments != nil {
			var untrusted []string
			for _, arg := range versionJSON.Arguments.JVM {
				untrusted = append(untrusted, resolveJVMArg(arg, nativesDir, mcDir, classpath, versionID)...)
			}
			// arguments.jvm 来自 Mojang/加载器下发的版本 JSON，本质上是外部数据。
			// 被篡改或恶意的整合包版本 JSON 可在此塞入 -javaagent / -XX:OnError
			// 等参数，在 JVM 启动阶段直接执行任意代码（见 filterUntrustedJvmArgs）。
			safeJvmArgs, blockedJvmArgs, jvmArgTruncated := filterUntrustedJvmArgs(untrusted)
			jvmArgs = append(jvmArgs, safeJvmArgs...)
			for _, bad := range blockedJvmArgs {
				a.writeLog("已拦截版本 JSON 中的危险 JVM 参数: %s", bad)
			}
			if jvmArgTruncated {
				a.writeLog("版本 JSON 的 JVM 参数数量超过 %d，多余参数已丢弃", maxUntrustedJvmArgs)
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
		username = sanitizeLaunchUsername(currentUser.Username)
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

// maxUntrustedJvmArgs 限制“版本/加载器 JSON 提供的 JVM 参数”总条数。
// 官方版本 JSON 的 JVM 参数只有十几条；Windows CreateProcess 命令行上限约
// 32K 字符，异常巨大的参数表只会来自损坏或被篡改的文件，直接截断。
const maxUntrustedJvmArgs = 256

// dangerousJvmFlagPrefixes 是不允许由外部版本 JSON 提供的 JVM 参数前缀
// （统一小写匹配）。这些参数能在 JVM 启动阶段加载任意字节码/原生库、
// 执行外部命令或替换主类，等价于任意代码执行：
//   - -javaagent / -agentlib / -agentpath：加载 JVMTI/Java agent
//   - -XX:OnError / -XX:OnOutOfMemoryError：JVM 事件触发时执行系统命令
//   - -XX:VMOptionsFile：从外部文件追加 JVM 参数，绕过本过滤
//   - -XXaltjvm(s)：替换 JVM 实现目录
//   - -Xrunjdwp/-Xrunhprof 等旧式 -Xrun 代理：开放 JDWP 远程调试即等同 RCE
//   - -jar / -m(--module)：改由攻击者指定的 jar/模块作为入口运行
//
// 启动器自身生成的 -Xmx、-Djava.library.path、-cp、--add-opens 等在过滤
// 完成之后才追加，不受影响；官方加载器使用的 -p/--module-path、--add-modules、
// --enable-native-access 不在列表中。
// 危险 JVM 参数的权威判定已抽到 jvmargs.go 的 jvmArgThreat，
// 在原 -javaagent 等前缀之外补齐了 @argfile / -noverify / 动态 agent 加载等绕过形态。

// isDangerousJvmFlag 判断单个 JVM 参数是否命中危险前缀。
// 兼容 "flag:operand"、"flag=operand" 和 "flag operand"（下一条参数）两种写法。
func isDangerousJvmFlag(lower string) bool {
	dangerous, _ := jvmArgThreat(lower)
	return dangerous
}

// filterUntrustedJvmArgs 过滤来自外部版本 JSON 的 JVM 参数。
// 返回安全参数、被拦截参数（用于日志）以及是否因超过上限而截断。
// 当危险参数以"独立 token + 下一参数为操作数"形式出现（如 -jar evil.jar），
// 操作数参数会一并丢弃。
func filterUntrustedJvmArgs(args []string) (safe []string, blocked []string, truncated bool) {
	skipOperand := false
	for i, arg := range args {
		if skipOperand {
			skipOperand = false
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(arg))
		dangerous, consumesOperand := jvmArgThreat(lower)
		if dangerous {
			blocked = append(blocked, arg)
			// 独立 token 形式时，下一条参数是其操作数（路径/命令），一并跳过。
			if consumesOperand {
				skipOperand = true
			}
			continue
		}
		safe = append(safe, arg)
		if len(safe) >= maxUntrustedJvmArgs {
			truncated = i+1 < len(args)
			break
		}
	}
	return safe, blocked, truncated
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

// sanitizePathComponent 验证路径组件不含路径遍历字符
func sanitizePathComponent(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("无效的路径组件: %s", name)
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\:*?"<>|`) {
		return fmt.Errorf("无效的路径组件: %s", name)
	}
	return nil
}

func (a *App) LaunchGame(versionID string) error {
	if err := sanitizePathComponent(versionID); err != nil {
		return fmt.Errorf("无效的版本ID: %v", err)
	}
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)
	a.launchLogPath = filepath.Join(versionDir, "QGL", "Logs", "qgl_launch.log")
	a.writeLog("===== 启动游戏: %s =====", versionID)
	a.writeLog("版本目录: %s", versionDir)

	// 拉起 JVM 前对 mods 目录做存量安全扫描（通用恶意形态 + Log4Shell/JNDI），
	// 覆盖手动拖入 / 其它启动器写入、从未经本程序校验的 jar；命中高危直接拒绝启动。
	if err := a.enforceInstalledModsBeforeLaunch(versionID); err != nil {
		return err
	}

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
				if isHTTPSURL(serverURL) {
					resp, err := safeHTTPClient().Get(serverURL)
					if err == nil {
						// 皮肤站首页本应几 KB；限制 1 MiB，防止恶意服务器返回几十 MB 把 JVM 命令行撑爆
						body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAuthlibPrefetchBytes))
						resp.Body.Close()
						if len(body) < int(maxAuthlibPrefetchBytes) {
							prefetched = base64.StdEncoding.EncodeToString(body)
						}
					}
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

	cmdParts := []string{syscall.EscapeArg(javaPath)}
	for _, arg := range allArgs {
		cmdParts = append(cmdParts, syscall.EscapeArg(arg))
	}
	fullCmdLine := strings.Join(cmdParts, " ")
	a.writeLog("命令行长度: %d 字符", len(fullCmdLine))

	cmd := exec.Command(javaPath)
	cmd.Dir = gameDir
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: fullCmdLine}

	// 子进程默认会继承启动器的全部环境变量，而 JAVA_TOOL_OPTIONS /
	// _JAVA_OPTIONS / JDK_JAVA_OPTIONS 等会被 JVM 在启动时自动当作额外参数
	// 加载，绕过我们对版本 JSON 与 JVM 参数的危险参数过滤（可注入任意
	// javaagent / 本地代理）。这里显式下发净化后的环境，只剥掉这一族变量。
	gameEnv, strippedEnv := currentGameEnvironment(nil)
	cmd.Env = gameEnv
	for _, name := range strippedEnv {
		a.writeLog("安全: 已从游戏进程环境中剥离隐式 JVM 参数变量: %s", name)
	}
	if len(strippedEnv) > 0 {
		// 只记录变量名（值可能含敏感路径/令牌），作为"环境被人动过"的留痕。
		recordSecurityEvent(auditCategoryJVMEnv, auditSeverityWarn, auditActionStripped,
			"minecraft", "启动游戏时剥离隐式 JVM 参数环境变量: "+strings.Join(strippedEnv, ","))
	}

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
	if err := sanitizePathComponent(versionID); err != nil {
		return "", fmt.Errorf("无效的版本ID: %v", err)
	}
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

	cmdParts := []string{syscall.EscapeArg(javaPath)}
	for _, arg := range allArgs {
		cmdParts = append(cmdParts, syscall.EscapeArg(arg))
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
					runtime.EventsEmit(a.ctx, "crashInfo", sanitizeLogLine(fmt.Sprintf("游戏启动失败，进程立即退出 (退出码: %d)%s", exitCode, logContext)))
				} else {
					runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
					runtime.EventsEmit(a.ctx, "crashInfo", sanitizeLogLine(fmt.Sprintf("游戏进程意外退出 (退出码: %d)%s", exitCode, logContext)))
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
			runtime.EventsEmit(a.ctx, "crashInfo", sanitizeLogLine(crashReason))
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
