package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ===== PCL / PCL CE 数据迁移 =====

// MigrateUserResult 用户迁移结果
type MigrateUserResult struct {
	Imported int      `json:"imported"` // 成功导入的离线用户数
	Skipped  int      `json:"skipped"`  // 跳过的数量（已存在或无法迁移的正版/外置账号）
	Names    []string `json:"names"`    // 导入的用户名列表
}

// pclCEProfilesPath 获取 PCL CE 的 Profiles.json 路径
func pclCEProfilesPath() string {
	appdata := os.Getenv("APPDATA")
	return filepath.Join(appdata, ".PCLCE", "Profiles.json")
}

// MigrateFromPCLCE 从 PCL CE 迁移用户数据
// 读取 %APPDATA%\.PCLCE\Profiles.json，导入所有离线档案（明文）
// 正版/外置档案的令牌是本机硬件加密的，无法迁移，只能统计数量提示用户重新登录
func (a *App) MigrateFromPCLCE() (MigrateUserResult, error) {
	result := MigrateUserResult{Names: []string{}}

	data, err := os.ReadFile(pclCEProfilesPath())
	if err != nil {
		return result, fmt.Errorf("未找到 PCL CE 的档案文件（Profiles.json），请确认已安装 PCL CE")
	}

	var profiles struct {
		LastUsed int `json:"lastUsed"`
		Profiles []struct {
			Type     string `json:"type"`
			Username string `json:"username"`
			Desc     string `json:"desc"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(data, &profiles); err != nil {
		return result, fmt.Errorf("解析 PCL CE 档案文件失败: %w", err)
	}

	for _, p := range profiles.Profiles {
		username := strings.TrimSpace(p.Username)
		if username == "" {
			continue
		}
		// 只迁移离线档案；type 为空时也按离线处理
		if p.Type != "" && p.Type != "offline" {
			result.Skipped++
			continue
		}
		// 已存在同名同类型用户则跳过（随机文件夹机制下按注册表判断）
		if a.findUserByNameAndType(username, UserTypeOffline) != nil {
			result.Skipped++
			continue
		}
		// 创建离线用户（不设密码，文件夹名为随机字符串）
		dir, err := a.CreateUser(username, "")
		if err != nil {
			result.Skipped++
			continue
		}
		if err := a.saveUserType(dir, UserTypeOffline); err != nil {
			result.Skipped++
			continue
		}
		// PCL 默认开启版本隔离，迁移的用户保持一致
		if err := a.SaveUserConfig(dir, &UserConfig{VersionIsolation: true}); err != nil {
			result.Skipped++
			continue
		}
		result.Imported++
		result.Names = append(result.Names, username)
	}

	return result, nil
}

// SelectPclExe 弹出文件选择框选择 PCL 的可执行文件（PCL.exe / PCLCE.exe）
func (a *App) SelectPclExe() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 PCL 启动器的可执行文件",
		Filters: []runtime.FileFilter{
			{DisplayName: "PCL 启动器", Pattern: "*.exe"},
		},
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// SelectMinecraftDir 弹出文件夹选择框选择 .minecraft 目录
func (a *App) SelectMinecraftDir() (string, error) {
	path, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 .minecraft 文件夹",
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// GetPclCEMcDir 自动获取 PCL CE 的游戏目录
// 读取 %APPDATA%\.PCLCE\Config.json 中的 LaunchFolders（格式 "名称>路径"），失败则搜索常见位置取第一个结果
func (a *App) GetPclCEMcDir() (string, error) {
	// 1) PCL CE 本地配置
	cfgPath := filepath.Join(os.Getenv("APPDATA"), ".PCLCE", "Config.json")
	if data, err := os.ReadFile(cfgPath); err == nil {
		var m map[string]interface{}
		if json.Unmarshal(data, &m) == nil {
			if v, ok := m["LaunchFolders"]; ok {
				// 格式: "pclce>D:\pclce\.minecraft\"，取 > 后面的路径
				raw := strings.TrimSpace(fmt.Sprint(v))
				if idx := strings.Index(raw, ">"); idx >= 0 {
					raw = strings.TrimSpace(raw[idx+1:])
				}
				if raw != "" {
					// 去掉末尾的反斜杠/斜杠
					raw = strings.TrimRight(raw, `/\`)
					if info, err := os.Stat(raw); err == nil && info.IsDir() {
						return raw, nil
					}
				}
			}
		}
	}

	// 2) 常见位置搜索，取第一个 .minecraft
	results, _ := a.SearchMinecraftFolders()
	if len(results) > 0 {
		return results[0].Path, nil
	}

	return "", fmt.Errorf("未能自动获取游戏目录，请手动选择 .minecraft 文件夹")
}

// GetPclMcDir 从 PCL 的配置中读取游戏目录
// PCL 配置位于 PCL.exe 所在目录的 PCL\Setup.ini，格式为无 section 的 key:value 行
// 只取 LaunchFolderSelect（游戏目录）
func (a *App) GetPclMcDir(pclExePath string) (string, error) {
	pclExePath = strings.TrimSpace(pclExePath)
	if pclExePath == "" {
		return "", fmt.Errorf("请先选择 PCL 可执行文件")
	}
	if _, err := os.Stat(pclExePath); err != nil {
		return "", fmt.Errorf("PCL 可执行文件不存在: %s", pclExePath)
	}

	setupPath := filepath.Join(filepath.Dir(pclExePath), "PCL", "Setup.ini")
	data, err := os.ReadFile(setupPath)
	if err != nil {
		return "", fmt.Errorf("未找到 PCL 配置文件（PCL\\Setup.ini），请确认选择的是 PCL 启动器")
	}

	// 解析 key:value 行
	mcDir := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if key == "LaunchFolderSelect" && value != "" {
			mcDir = value
		}
	}

	if mcDir == "" {
		return "", fmt.Errorf("PCL 配置中没有设置游戏目录（LaunchFolderSelect）")
	}

	// 校验目录存在
	if info, err := os.Stat(mcDir); err != nil || !info.IsDir() {
		return "", fmt.Errorf("PCL 的游戏目录不存在: %s", mcDir)
	}

	return mcDir, nil
}

// MigrateMinecraftDir 迁移 .minecraft 目录
// mode = "full"：完整迁移，复制整个 .minecraft 到 QGL 目录（独立副本，PCL 出问题不影响 QGL）
// mode = "minimal"：最小迁移，仅把 QGL 的游戏目录指向 PCL 的 .minecraft（共用，PCL 出问题 QGL 一起出问题）
// 返回迁移后的实际游戏目录
func (a *App) MigrateMinecraftDir(srcDir string, mode string) (string, error) {
	srcDir = strings.TrimSpace(srcDir)
	if srcDir == "" {
		return "", fmt.Errorf("请先选择 .minecraft 文件夹")
	}
	info, err := os.Stat(srcDir)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("目录不存在: %s", srcDir)
	}

	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}

	var finalDir string
	if mode == "minimal" {
		// 最小迁移：直接指向原目录
		config.MinecraftDir = srcDir
		finalDir = srcDir
	} else {
		// 完整迁移：复制到 QGL 目录
		targetDir := filepath.Join(a.GetQGLDir(), ".minecraft")
		if err := copyDirRecursive(srcDir, targetDir); err != nil {
			return "", fmt.Errorf("复制 .minecraft 失败: %w", err)
		}
		config.MinecraftDir = ""
		finalDir = targetDir
	}

	// 注意：不修改辅助模式状态，辅助模式必须由用户手动进入

	if err := a.SaveGlobalConfig(config); err != nil {
		return "", err
	}
	return finalDir, nil
}

// copyDirRecursive 递归复制目录（已存在则合并覆盖）
func copyDirRecursive(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		// 跳过 PCL 自己的缓存/标记文件（PCL.ini、PCL 文件夹），这些不属于游戏数据
		relLower := strings.ToLower(rel)
		if relLower == "pcl.ini" || strings.HasPrefix(relLower, "pcl\\") || strings.HasPrefix(relLower, "pcl/") {
			return nil
		}

		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		dstFile, err := os.Create(target)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		_, err = io.Copy(dstFile, srcFile)
		return err
	})
}
