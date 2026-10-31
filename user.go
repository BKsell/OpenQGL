package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// UserType 用户类型
type UserType string

const (
	UserTypeGuest    UserType = "guest"    // 访客用户
	UserTypeOffline  UserType = "offline"  // 离线用户
	UserTypePremium  UserType = "premium"  // 正版用户
	UserTypeExternal UserType = "external" // 外置用户（Yggdrasil）
)

// UserInfo 用户信息
type UserInfo struct {
	Username    string   `json:"username"`
	Dir         string   `json:"dir"`       // 用户文件夹名（随机字符串，作为用户唯一标识）
	HasPassword bool     `json:"hasPassword"`
	Type        UserType `json:"type"`
	IsLocked    bool     `json:"isLocked"`
	ServerName  string   `json:"serverName"` // 外置用户的服务器名称
	ServerURL   string   `json:"serverUrl"`  // 外置用户的验证服务器地址（令牌过期重新登录时预填）
}

// UserEntry 用户注册表条目（QGL/Users/user.json）
// name 为显示用户名（可重复），dir 为随机文件夹名（唯一标识），
// 这样不同模式的用户即使同名也不会互相覆盖
type UserEntry struct {
	Name string   `json:"name"` // 显示用户名
	Type UserType `json:"type"` // 用户类型
	Dir  string   `json:"dir"`  // 用户文件夹名（随机字符串）
}

// userRegistryPath 用户注册表路径
func (a *App) userRegistryPath() string {
	return filepath.Join(a.GetUsersDir(), "user.json")
}

// randomDirName 生成随机文件夹名（16 位十六进制）
func randomDirName() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// loadUserRegistry 读取用户注册表；若不存在 user.json 且有旧版用户文件夹则自动迁移转换
func (a *App) loadUserRegistry() []UserEntry {
	data, err := os.ReadFile(a.userRegistryPath())
	if err == nil {
		var entries []UserEntry
		if json.Unmarshal(data, &entries) == nil && entries != nil {
			return entries
		}
	}
	// 迁移：旧版以用户名作为文件夹名，转换为随机文件夹名
	return a.migrateUserRegistry()
}

// migrateUserRegistry 旧版用户目录迁移：文件夹名(用户名) -> 随机文件夹名 + user.json 注册表
func (a *App) migrateUserRegistry() []UserEntry {
	usersDir := a.GetUsersDir()
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return []UserEntry{}
	}

	var result []UserEntry
	migrated := false
	oldCurrent := ""
	if config, err := a.GetGlobalConfig(); err == nil {
		oldCurrent = config.CurrentUser
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		oldName := entry.Name()
		newDir := randomDirName()
		// 文件夹重命名失败（如被占用）则保留原名，同样注册进注册表，不影响使用
		if renameErr := os.Rename(filepath.Join(usersDir, oldName), filepath.Join(usersDir, newDir)); renameErr == nil {
			migrated = true
		} else {
			newDir = oldName
		}
		userType := a.readLegacyUserType(filepath.Join(usersDir, newDir))
		result = append(result, UserEntry{Name: oldName, Type: userType, Dir: newDir})
		// 同步修正全局配置中的当前用户
		if oldCurrent == oldName {
			if config, err := a.GetGlobalConfig(); err == nil {
				config.CurrentUser = newDir
				a.SaveGlobalConfig(config)
			}
		}
	}

	a.saveUserRegistry(result)
	if migrated && len(result) > 0 {
		a.writeLog("用户目录已迁移到随机文件夹名机制（共 %d 个用户）", len(result))
	}
	return result
}

// readLegacyUserType 从用户文件夹的 type.json 读取用户类型（迁移用）
func (a *App) readLegacyUserType(userDir string) UserType {
	data, err := os.ReadFile(filepath.Join(userDir, "type.json"))
	if err != nil {
		return UserTypeOffline
	}
	var typeData struct {
		Type UserType `json:"type"`
	}
	if json.Unmarshal(data, &typeData) != nil {
		return UserTypeOffline
	}
	return typeData.Type
}

// saveUserRegistry 保存用户注册表
func (a *App) saveUserRegistry(entries []UserEntry) error {
	os.MkdirAll(a.GetUsersDir(), 0755)
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.userRegistryPath(), data, 0644)
}

// findUserEntry 按标识（dir）查找注册表条目
func (a *App) findUserEntry(id string) *UserEntry {
	entries := a.loadUserRegistry()
	for i := range entries {
		if entries[i].Dir == id {
			return &entries[i]
		}
	}
	return nil
}

// userNameByID 按标识（dir）查显示用户名（查不到返回原值，兼容迁移前调用）
func (a *App) userNameByID(id string) string {
	if entry := a.findUserEntry(id); entry != nil {
		return entry.Name
	}
	return id
}

// userDirFor 用户文件夹路径（标识 = 随机文件夹名）
func (a *App) userDirFor(id string) string {
	return filepath.Join(a.GetUsersDir(), id)
}

// ExternalAuthData 外置登录认证数据
type ExternalAuthData struct {
	ServerURL    string `json:"serverUrl"`    // Yggdrasil API 服务器地址（如 https://littleskin.cn/api/yggdrasil）
	AccessToken  string `json:"accessToken"`  // 访问令牌
	ClientToken  string `json:"clientToken"`  // 客户端令牌
	UUID         string `json:"uuid"`         // 玩家 UUID
	Username     string `json:"username"`     // 游戏内用户名
	Password     string `json:"password"`     // 登录密码（加密存储，用于刷新令牌）
	ServerName   string `json:"serverName"`   // 服务器显示名称
}

// PasswordData 密码数据
type PasswordData struct {
	PasswordMD5 string `json:"passwordMD5"`
}

// UserConfig 用户配置（每个用户独立）
type UserConfig struct {
	VersionIsolation         bool   `json:"versionIsolation"`
	SelectedVersion          string `json:"selectedVersion"`
	ThemeColor               string `json:"themeColor"`               // 主题色: blue, cyan, pink, purple, orange, yellow, green
	BackgroundImage          string `json:"backgroundImage"`           // 自定义背景图片路径，留空则使用默认
	ShowExportLaunchCommand  bool   `json:"showExportLaunchCommand"`   // 显示导出启动命令按钮
	OOBE                     bool   `json:"oobe"`                      // 用户向导是否已完成
}

// GlobalConfig 全局配置
type GlobalConfig struct {
	CurrentUser      string `json:"currentUser"`
	JavaPath         string `json:"javaPath"`
	MaxMemory        int    `json:"maxMemory"`
	MinMemory        int    `json:"minMemory"`
	MinecraftDir     string `json:"minecraftDir"`     // 自定义 .minecraft 目录，留空则使用默认路径
	PortableMode     bool   `json:"portableMode"`     // 便携版模式：优先使用 QGL\pe\java\bin\java.exe
	HelperMode       bool   `json:"helperMode"`       // 辅助模式：下载安装到外部 .minecraft（绕过 PCL/HMCL）
	HelperModeDir    string `json:"helperModeDir"`    // 辅助模式指定的 .minecraft 目录
	OOBE             bool   `json:"oobe"`             // OOBE 首次设置向导是否已完成
}

// GetOOBEDone 是否已完成 OOBE 首次设置向导
func (a *App) GetOOBEDone() (bool, error) {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return false, err
	}
	return config.OOBE, nil
}

// SetOOBEDone 标记 OOBE 已完成
func (a *App) SetOOBEDone() error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}
	config.OOBE = true
	return a.SaveGlobalConfig(config)
}

func (a *App) GetAppDir() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exePath)
}

func (a *App) GetQGLDir() string {
	return filepath.Join(a.GetAppDir(), "QGL")
}

func (a *App) GetUsersDir() string {
	return filepath.Join(a.GetQGLDir(), "Users")
}

// GetPortableJavaPath 获取便携版 Java 路径
func (a *App) GetPortableJavaPath() string {
	return filepath.Join(a.GetQGLDir(), "pe", "java", "bin", "java.exe")
}

// IsPortableMode 是否启用便携版模式
func (a *App) IsPortableMode() bool {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return false
	}
	return config.PortableMode
}

// SetPortableMode 设置便携版模式
func (a *App) SetPortableMode(enabled bool) error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return err
	}
	config.PortableMode = enabled
	return a.SaveGlobalConfig(config)
}

// GetPortableJavaInfo 获取便携版 Java 信息（如果存在）
func (a *App) GetPortableJavaInfo() *JavaEntry {
	javaPath := a.GetPortableJavaPath()
	if _, err := os.Stat(javaPath); err != nil {
		return nil
	}
	return validateJava(javaPath)
}

func (a *App) GetMinecraftDir() string {
	// 辅助模式：使用用户指定的外部 .minecraft 目录（绕过 PCL/HMCL 直接安装）
	config, err := a.GetGlobalConfig()
	if err == nil && config.HelperMode && config.HelperModeDir != "" {
		return config.HelperModeDir
	}
	// 优先使用自定义路径
	if err == nil && config.MinecraftDir != "" {
		return config.MinecraftDir
	}
	return filepath.Join(a.GetQGLDir(), ".minecraft")
}

func (a *App) CheckFirstRun() bool {
	usersDir := a.GetUsersDir()
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return true
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return false
		}
	}
	return true
}

// GetUserType 获取用户类型（参数为用户标识 dir）
func (a *App) GetUserType(id string) UserType {
	if entry := a.findUserEntry(id); entry != nil {
		return entry.Type
	}
	return a.readLegacyUserType(a.userDirFor(id))
}

// saveUserType 保存用户类型（参数为用户标识 dir，同步更新注册表）
func (a *App) saveUserType(id string, userType UserType) error {
	userDir := a.userDirFor(id)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return err
	}
	typeData := struct {
		Type UserType `json:"type"`
	}{Type: userType}
	data, err := json.MarshalIndent(typeData, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(userDir, "type.json"), data, 0644); err != nil {
		return err
	}
	// 同步注册表
	entries := a.loadUserRegistry()
	for i := range entries {
		if entries[i].Dir == id {
			entries[i].Type = userType
			break
		}
	}
	return a.saveUserRegistry(entries)
}

func (a *App) GetUsers() ([]UserInfo, error) {
	entries := a.loadUserRegistry()

	var users []UserInfo
	for _, entry := range entries {
		hasPwd, err := a.UserHasPassword(entry.Dir)
		if err != nil {
			hasPwd = false
		}
		userType := entry.Type
		isLocked := false
		if userType == UserTypeGuest {
			isLocked = !a.guestUnlocked
		}
		serverName := ""
		serverURL := ""
		if userType == UserTypeExternal {
			extData, extErr := a.GetExternalAuthData(entry.Dir)
			if extErr == nil {
				serverName = extData.ServerName
				serverURL = extData.ServerURL
			}
		}
		users = append(users, UserInfo{
			Username:    entry.Name,
			Dir:         entry.Dir,
			HasPassword: hasPwd,
			Type:        userType,
			IsLocked:    isLocked,
			ServerName:  serverName,
			ServerURL:   serverURL,
		})
	}
	return users, nil
}

// CreateGuestUser 创建访客用户（需要安全密码），返回用户标识 dir
func (a *App) CreateGuestUser(username string, securityPassword string) (string, error) {
	if securityPassword == "" {
		return "", fmt.Errorf("访客用户必须设置安全密码")
	}
	dir, err := a.CreateUser(username, "")
	if err != nil {
		return "", err
	}
	// 访客用户的密码文件存储安全密码
	userDir := a.userDirFor(dir)
	hash := md5.Sum([]byte(securityPassword))
	pwdData := PasswordData{
		PasswordMD5: fmt.Sprintf("%x", hash),
	}
	pwdBytes, err := json.MarshalIndent(pwdData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化密码数据失败: %w", err)
	}
	pwdPath := filepath.Join(userDir, "password.json")
	if err := os.WriteFile(pwdPath, pwdBytes, 0644); err != nil {
		return "", fmt.Errorf("写入密码文件失败: %w", err)
	}
	// 保存用户类型为访客
	return dir, a.saveUserType(dir, UserTypeGuest)
}

// CreateOfflineUser 创建离线用户（可选密码），返回用户标识 dir
func (a *App) CreateOfflineUser(username string, password string) (string, error) {
	dir, err := a.CreateUser(username, password)
	if err != nil {
		return "", err
	}
	return dir, a.saveUserType(dir, UserTypeOffline)
}

// CreatePremiumUser 创建正版用户，返回用户标识 dir
func (a *App) CreatePremiumUser(username string, authData MSAuthData) (string, error) {
	// 用户已存在（令牌过期重新登录）：只更新 ms_auth.json，不重置用户配置
	// 按 显示用户名+类型 在注册表中查找，同名不同类型的用户互不影响
	if entry := a.findUserByNameAndType(username, UserTypePremium); entry != nil {
		if err := a.SaveMSAuthData(entry.Dir, &authData); err != nil {
			return "", err
		}
		return entry.Dir, a.saveUserType(entry.Dir, UserTypePremium)
	}
	// 创建用户目录和基础配置（不设置密码）
	dir, err := a.CreateUser(username, "")
	if err != nil {
		return "", err
	}
	// 保存用户类型为正版
	if err := a.saveUserType(dir, UserTypePremium); err != nil {
		return "", err
	}
	// 保存微软认证数据
	return dir, a.SaveMSAuthData(dir, &authData)
}

// CreateExternalUser 创建外置用户，返回用户标识 dir
func (a *App) CreateExternalUser(username string, authData ExternalAuthData) (string, error) {
	// 按 显示用户名+类型 在注册表中查找（外置登录令牌过期重加场景）
	if entry := a.findUserByNameAndType(username, UserTypeExternal); entry != nil {
		if err := a.SaveExternalAuthData(entry.Dir, &authData); err != nil {
			return "", err
		}
		return entry.Dir, nil
	}
	dir, err := a.CreateUser(username, "")
	if err != nil {
		return "", err
	}
	if err := a.saveUserType(dir, UserTypeExternal); err != nil {
		return "", err
	}
	return dir, a.SaveExternalAuthData(dir, &authData)
}

// findUserByNameAndType 按显示用户名+类型查找注册表条目（同名不同类型不冲突）
func (a *App) findUserByNameAndType(name string, userType UserType) *UserEntry {
	entries := a.loadUserRegistry()
	for i := range entries {
		if entries[i].Name == name && entries[i].Type == userType {
			return &entries[i]
		}
	}
	return nil
}

// SaveExternalAuthData 保存外置登录认证数据（加密存储，和正版账号一样；参数为用户标识 dir）
func (a *App) SaveExternalAuthData(id string, authData *ExternalAuthData) error {
	userDir := a.userDirFor(id)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}

	// 构建需要加密的数据（除 serverName 以外的敏感字段）
	encryptPayload := map[string]interface{}{
		"serverUrl":   authData.ServerURL,
		"accessToken": authData.AccessToken,
		"clientToken": authData.ClientToken,
		"uuid":        authData.UUID,
		"username":    authData.Username,
		"password":    authData.Password,
	}
	payloadBytes, err := json.Marshal(encryptPayload)
	if err != nil {
		return fmt.Errorf("序列化外置认证数据失败: %w", err)
	}

	// 加密（密钥基于显示用户名，迁移重命名文件夹后仍可解密）
	key := getEncryptionKey(a.userNameByID(id))
	encrypted, err := aesGCMEncrypt(payloadBytes, key)
	if err != nil {
		return fmt.Errorf("加密外置认证数据失败: %w", err)
	}

	// 构建加密后的存储格式
	encData := ExternalAuthDataEncrypted{
		ServerName: authData.ServerName,
		Data:       encrypted,
	}

	data, err := json.MarshalIndent(encData, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化加密数据失败: %w", err)
	}
	return os.WriteFile(filepath.Join(userDir, "external_auth.json"), data, 0644)
}

// GetExternalAuthData 获取外置登录认证数据（解密读取；参数为用户标识 dir）
func (a *App) GetExternalAuthData(id string) (*ExternalAuthData, error) {
	userDir := a.userDirFor(id)
	data, err := os.ReadFile(filepath.Join(userDir, "external_auth.json"))
	if err != nil {
		return nil, fmt.Errorf("读取外置认证数据失败: %w", err)
	}

	// 先尝试按加密格式解析
	var encData ExternalAuthDataEncrypted
	if err := json.Unmarshal(data, &encData); err == nil && encData.Data != "" {
		// 加密格式：解密 Data 字段（密钥基于显示用户名）
		key := getEncryptionKey(a.userNameByID(id))
		decrypted, err := aesGCMDecrypt(encData.Data, key)
		if err != nil {
			return nil, fmt.Errorf("解密外置认证数据失败: %w", err)
		}
		var authData ExternalAuthData
		if err := json.Unmarshal(decrypted, &authData); err != nil {
			return nil, fmt.Errorf("解析解密后的外置认证数据失败: %w", err)
		}
		authData.ServerName = encData.ServerName // 服务器名称不加密
		return &authData, nil
	}

	// 兼容旧版明文格式
	var authData ExternalAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		return nil, fmt.Errorf("解析外置认证数据失败: %w", err)
	}
	return &authData, nil
}

// CreateUser 创建用户基础方法：文件夹名使用随机字符串，注册进 user.json，返回用户标识 dir
func (a *App) CreateUser(username string, password string) (string, error) {
	dir := randomDirName()
	userDir := a.userDirFor(dir)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return "", fmt.Errorf("创建用户目录失败: %w", err)
	}

	// 注册进用户注册表（显示名可重复，dir 唯一）
	entries := a.loadUserRegistry()
	entries = append(entries, UserEntry{Name: username, Type: UserTypeOffline, Dir: dir})
	if err := a.saveUserRegistry(entries); err != nil {
		return "", fmt.Errorf("写入用户注册表失败: %w", err)
	}

	if password != "" {
		hash := md5.Sum([]byte(password))
		pwdData := PasswordData{
			PasswordMD5: fmt.Sprintf("%x", hash),
		}
		pwdBytes, err := json.MarshalIndent(pwdData, "", "  ")
		if err != nil {
			return "", fmt.Errorf("序列化密码数据失败: %w", err)
		}
		pwdPath := filepath.Join(userDir, "password.json")
		if err := os.WriteFile(pwdPath, pwdBytes, 0644); err != nil {
			return "", fmt.Errorf("写入密码文件失败: %w", err)
		}
	}

	defaultConfig := UserConfig{
		VersionIsolation: false,
		SelectedVersion:  "",
	}
	configBytes, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化用户配置失败: %w", err)
	}
	configPath := filepath.Join(userDir, "config.json")
	if err := os.WriteFile(configPath, configBytes, 0644); err != nil {
		return "", fmt.Errorf("写入用户配置文件失败: %w", err)
	}

	return dir, nil
}

// LoginUser 登录用户（参数为用户标识 dir）
func (a *App) LoginUser(id string, password string) error {
	userType := a.GetUserType(id)

	if userType == UserTypeGuest {
		// 访客用户：不需要密码即可进入，但进入后处于锁定状态
		a.guestUnlocked = false
		return a.SetCurrentUser(id)
	}

	if userType == UserTypePremium {
		// 正版用户：刷新令牌，如果刷新失败则需要重新登录
		if err := a.RefreshMicrosoftToken(id); err != nil {
			return fmt.Errorf("正版令牌已过期，请重新登录: %v", err)
		}
		return a.SetCurrentUser(id)
	}

	if userType == UserTypeExternal {
		// 外置用户：刷新令牌
		if err := a.RefreshExternalToken(id); err != nil {
			return fmt.Errorf("外置登录令牌已过期，请重新登录: %v", err)
		}
		return a.SetCurrentUser(id)
	}

	// 离线用户：正常密码验证
	hasPwd, err := a.UserHasPassword(id)
	if err != nil {
		return fmt.Errorf("检查用户密码失败: %w", err)
	}

	if hasPwd {
		if password == "" {
			return fmt.Errorf("该用户已设置密码，请输入密码")
		}
		pwdPath := filepath.Join(a.userDirFor(id), "password.json")
		pwdBytes, err := os.ReadFile(pwdPath)
		if err != nil {
			return fmt.Errorf("读取密码文件失败: %w", err)
		}
		var pwdData PasswordData
		if err := json.Unmarshal(pwdBytes, &pwdData); err != nil {
			return fmt.Errorf("解析密码文件失败: %w", err)
		}
		hash := md5.Sum([]byte(password))
		inputMD5 := fmt.Sprintf("%x", hash)
		if inputMD5 != pwdData.PasswordMD5 {
			return fmt.Errorf("密码错误")
		}
	} else {
		if password != "" {
			return fmt.Errorf("该用户未设置密码，无需输入密码")
		}
	}

	return a.SetCurrentUser(id)
}

// UnlockGuest 解锁访客用户（输入安全密码）
func (a *App) UnlockGuest(securityPassword string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	if currentUser.Type != UserTypeGuest {
		return fmt.Errorf("当前用户不是访客用户")
	}
	if securityPassword == "" {
		return fmt.Errorf("请输入安全密码")
	}

	userDir := a.userDirFor(currentUser.Dir)
	pwdPath := filepath.Join(userDir, "password.json")
	pwdBytes, err := os.ReadFile(pwdPath)
	if err != nil {
		return fmt.Errorf("读取安全密码文件失败: %w", err)
	}
	var pwdData PasswordData
	if err := json.Unmarshal(pwdBytes, &pwdData); err != nil {
		return fmt.Errorf("解析安全密码文件失败: %w", err)
	}
	hash := md5.Sum([]byte(securityPassword))
	inputMD5 := fmt.Sprintf("%x", hash)
	if inputMD5 != pwdData.PasswordMD5 {
		return fmt.Errorf("安全密码错误")
	}

	a.guestUnlocked = true
	return nil
}

// IsGuestLocked 检查当前访客用户是否锁定
func (a *App) IsGuestLocked() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	if currentUser.Type != UserTypeGuest {
		return false
	}
	return !a.guestUnlocked
}

// LockGuest 重新锁定访客用户
func (a *App) LockGuest() {
	a.guestUnlocked = false
}

// ===== 用户管理（管理当前用户）=====

// getUserPasswordMD5 读取用户密码 MD5（无密码返回 ""；参数为用户标识 dir）
func (a *App) getUserPasswordMD5(id string) string {
	pwdPath := filepath.Join(a.userDirFor(id), "password.json")
	pwdBytes, err := os.ReadFile(pwdPath)
	if err != nil {
		return ""
	}
	var pwdData PasswordData
	if json.Unmarshal(pwdBytes, &pwdData) != nil {
		return ""
	}
	return pwdData.PasswordMD5
}

// SetUserPassword 设置/修改当前用户的密码
// 有原密码时必须先验证原密码；newPassword 为空则清除密码
func (a *App) SetUserPassword(oldPassword string, newPassword string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	userDir := a.userDirFor(currentUser.Dir)
	pwdPath := filepath.Join(userDir, "password.json")

	existingMD5 := a.getUserPasswordMD5(currentUser.Dir)
	if existingMD5 != "" {
		// 有密码：必须验证原密码
		if oldPassword == "" {
			return fmt.Errorf("请输入原密码")
		}
		hash := md5.Sum([]byte(oldPassword))
		if fmt.Sprintf("%x", hash) != existingMD5 {
			return fmt.Errorf("原密码错误")
		}
	}

	if newPassword == "" {
		// 清除密码
		if err := os.Remove(pwdPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("清除密码失败: %w", err)
		}
		return nil
	}

	if err := os.MkdirAll(userDir, 0755); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	hash := md5.Sum([]byte(newPassword))
	pwdData := PasswordData{PasswordMD5: fmt.Sprintf("%x", hash)}
	pwdBytes, err := json.MarshalIndent(pwdData, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化密码数据失败: %w", err)
	}
	if err := os.WriteFile(pwdPath, pwdBytes, 0644); err != nil {
		return fmt.Errorf("写入密码文件失败: %w", err)
	}
	return nil
}

// DeleteCurrentUser 删除当前用户账户
// 有密码时必须先验证密码（前端的确认弹窗为二次确认）
func (a *App) DeleteCurrentUser(password string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}

	existingMD5 := a.getUserPasswordMD5(currentUser.Dir)
	if existingMD5 != "" {
		if password == "" {
			return fmt.Errorf("该用户已设置密码，请输入密码")
		}
		hash := md5.Sum([]byte(password))
		if fmt.Sprintf("%x", hash) != existingMD5 {
			return fmt.Errorf("密码错误")
		}
	}

	// 清除全局当前用户，避免残留指向已删除的用户
	config, err := a.GetGlobalConfig()
	if err == nil {
		config.CurrentUser = ""
		a.SaveGlobalConfig(config)
	}

	// 从注册表移除该用户
	entries := a.loadUserRegistry()
	filtered := entries[:0]
	for _, e := range entries {
		if e.Dir != currentUser.Dir {
			filtered = append(filtered, e)
		}
	}
	a.saveUserRegistry(filtered)

	userDir := a.userDirFor(currentUser.Dir)
	if err := os.RemoveAll(userDir); err != nil {
		return fmt.Errorf("删除用户目录失败: %w", err)
	}

	a.writeLog("用户 %s 已删除", currentUser.Username)
	return nil
}

// ===== 访客权限管理（保存到访客用户目录的 guest.json）=====

// GuestPermissions 访客权限：控制访客锁定时可以使用哪些功能
// 注意：解锁状态下所有功能均可用，权限仅影响锁定状态
type GuestPermissions struct {
	AllowDownload bool `json:"allowDownload"` // 下载游戏
	AllowMod      bool `json:"allowMod"`      // MOD 管理
	AllowEasyQGL  bool `json:"allowEasyQGL"`  // Easy QGL
	AllowSettings bool `json:"allowSettings"` // 设置
	AllowQGLPlus  bool `json:"allowQGLPlus"`  // QGL+（一键开服/联机）
	AllowHelper   bool `json:"allowHelper"`   // 辅助模式
}

// DefaultGuestPermissions 默认访客权限（全部允许）
func DefaultGuestPermissions() GuestPermissions {
	return GuestPermissions{
		AllowDownload: true,
		AllowMod:      true,
		AllowEasyQGL:  true,
		AllowSettings: true,
		AllowQGLPlus:  true,
		AllowHelper:   true,
	}
}

// GetGuestPermissions 读取当前用户的访客权限（guest.json，不存在则返回默认全允许）
func (a *App) GetGuestPermissions() GuestPermissions {
	perms := DefaultGuestPermissions()
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return perms
	}
	guestPath := filepath.Join(a.userDirFor(currentUser.Dir), "guest.json")
	data, err := os.ReadFile(guestPath)
	if err != nil {
		return perms
	}
	var saved GuestPermissions
	if json.Unmarshal(data, &saved) == nil {
		return saved
	}
	return perms
}

// SetGuestPermissions 保存当前用户的访客权限到 guest.json
func (a *App) SetGuestPermissions(perms GuestPermissions) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	userDir := a.userDirFor(currentUser.Dir)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	guestPath := filepath.Join(userDir, "guest.json")
	data, err := json.MarshalIndent(perms, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化权限数据失败: %w", err)
	}
	if err := os.WriteFile(guestPath, data, 0644); err != nil {
		return fmt.Errorf("写入权限文件失败: %w", err)
	}
	return nil
}


func (a *App) SetCurrentUser(id string) error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}
	// CurrentUser 存储用户标识（随机文件夹名）
	config.CurrentUser = id
	return a.SaveGlobalConfig(config)
}

func (a *App) GetCurrentUser() (UserInfo, error) {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return UserInfo{}, fmt.Errorf("读取全局配置失败: %w", err)
	}
	if config.CurrentUser == "" {
		return UserInfo{}, fmt.Errorf("未设置当前用户")
	}
	// CurrentUser 为用户标识（随机文件夹名），从注册表解析显示用户名
	entry := a.findUserEntry(config.CurrentUser)
	displayName := config.CurrentUser
	if entry != nil {
		displayName = entry.Name
	}
	hasPwd, err := a.UserHasPassword(config.CurrentUser)
	if err != nil {
		hasPwd = false
	}
	userType := a.GetUserType(config.CurrentUser)
	isLocked := false
	if userType == UserTypeGuest {
		isLocked = !a.guestUnlocked
	}
	return UserInfo{
		Username:    displayName,
		Dir:         config.CurrentUser,
		HasPassword: hasPwd,
		Type:        userType,
		IsLocked:    isLocked,
	}, nil
}

func (a *App) UserHasPassword(id string) (bool, error) {
	pwdPath := filepath.Join(a.userDirFor(id), "password.json")
	info, err := os.Stat(pwdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("检查密码文件失败: %w", err)
	}
	if info.Size() == 0 {
		return false, nil
	}
	pwdBytes, err := os.ReadFile(pwdPath)
	if err != nil {
		return false, fmt.Errorf("读取密码文件失败: %w", err)
	}
	var pwdData PasswordData
	if err := json.Unmarshal(pwdBytes, &pwdData); err != nil {
		return false, nil
	}
	return pwdData.PasswordMD5 != "", nil
}

func (a *App) GetGlobalConfig() (*GlobalConfig, error) {
	configPath := filepath.Join(a.GetQGLDir(), "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &GlobalConfig{}, nil
		}
		return nil, fmt.Errorf("读取全局配置失败: %w", err)
	}
	var config GlobalConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析全局配置失败: %w", err)
	}
	return &config, nil
}

func (a *App) SaveGlobalConfig(config *GlobalConfig) error {
	qglDir := a.GetQGLDir()
	if err := os.MkdirAll(qglDir, 0755); err != nil {
		return fmt.Errorf("创建QGL目录失败: %w", err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化全局配置失败: %w", err)
	}
	configPath := filepath.Join(qglDir, "config.json")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("写入全局配置失败: %w", err)
	}
	return nil
}

func (a *App) GetUserConfig(id string) (*UserConfig, error) {
	configPath := filepath.Join(a.userDirFor(id), "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &UserConfig{}, nil
		}
		return nil, fmt.Errorf("读取用户配置失败: %w", err)
	}
	var config UserConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析用户配置失败: %w", err)
	}
	return &config, nil
}

func (a *App) SaveUserConfig(id string, config *UserConfig) error {
	userDir := a.userDirFor(id)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化用户配置失败: %w", err)
	}
	configPath := filepath.Join(userDir, "config.json")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("写入用户配置失败: %w", err)
	}
	return nil
}

func (a *App) IsVersionIsolation() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return false
	}
	return config.VersionIsolation
}

func (a *App) SetVersionIsolation(enabled bool) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return fmt.Errorf("读取用户配置失败: %w", err)
	}
	config.VersionIsolation = enabled
	return a.SaveUserConfig(currentUser.Dir, config)
}

func (a *App) GetSelectedVersion() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return ""
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return ""
	}
	return config.SelectedVersion
}

func (a *App) SetSelectedVersion(versionID string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		config = &UserConfig{}
	}
	config.SelectedVersion = versionID
	return a.SaveUserConfig(currentUser.Dir, config)
}

// GetThemeColor 获取当前用户的主题色
func (a *App) GetThemeColor() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return "cyan"
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil || config.ThemeColor == "" {
		return "cyan"
	}
	return config.ThemeColor
}

// GetUserOOBEDone 当前用户的用户向导是否已完成
func (a *App) GetUserOOBEDone() (bool, error) {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false, err
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return false, err
	}
	return config.OOBE, nil
}

// SetUserOOBEDone 标记当前用户的用户向导已完成
func (a *App) SetUserOOBEDone() error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return err
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		config = &UserConfig{}
	}
	config.OOBE = true
	return a.SaveUserConfig(currentUser.Dir, config)
}

// SetThemeColor 设置当前用户的主题色
func (a *App) SetThemeColor(color string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		config = &UserConfig{}
	}
	config.ThemeColor = color
	err = a.SaveUserConfig(currentUser.Dir, config)
	if err != nil {
		return err
	}
	runtime.EventsEmit(a.ctx, "themeChanged", color)
	return nil
}

// GetShowExportLaunchCommand 获取是否显示导出启动命令按钮
func (a *App) GetShowExportLaunchCommand() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return false
	}
	return config.ShowExportLaunchCommand
}

// SetShowExportLaunchCommand 设置是否显示导出启动命令按钮
func (a *App) SetShowExportLaunchCommand(show bool) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		config = &UserConfig{}
	}
	config.ShowExportLaunchCommand = show
	return a.SaveUserConfig(currentUser.Dir, config)
}

// GetBackgroundImage 获取当前用户的背景图片路径
func (a *App) GetBackgroundImage() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return ""
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return ""
	}
	return config.BackgroundImage
}

// SetBackgroundImage 设置当前用户的背景图片路径
func (a *App) SetBackgroundImage(path string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		config = &UserConfig{}
	}
	config.BackgroundImage = path
	err = a.SaveUserConfig(currentUser.Dir, config)
	if err != nil {
		return err
	}
	runtime.EventsEmit(a.ctx, "backgroundChanged", path)
	return nil
}

// SelectBackgroundImage 打开文件选择对话框选择背景图片
func (a *App) SelectBackgroundImage() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择背景图片",
		Filters: []runtime.FileFilter{
			{DisplayName: "图片文件", Pattern: "*.jpg;*.jpeg;*.png;*.bmp;*.webp"},
		},
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// GetBackgroundImageDataURL 获取背景图片的 base64 Data URL（用于 CSS background-image）
func (a *App) GetBackgroundImageDataURL() string {
	path := a.GetBackgroundImage()
	if path == "" || !fileExists(path) {
		return ""
	}
	url, err := a.fileToDataURL(path)
	if err != nil {
		return ""
	}
	return url
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetBingDailyImage 获取 Bing 每日壁纸图片
// 1. 请求 Bing API 获取重定向 URL
// 2. 跟随重定向获取实际图片
// 3. 缓存到本地并返回 data URL
func (a *App) GetBingDailyImage() (string, error) {
	cacheDir := filepath.Join(a.GetQGLDir(), "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("创建缓存目录失败: %w", err)
	}
	cachePath := filepath.Join(cacheDir, "bing_daily.jpg")

	// 请求 Bing API（会重定向到图片 URL）
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 不自动跟随重定向，我们需要获取最终的图片 URL
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get("https://bing.biturl.top/?resolution=1920&format=image&index=0&mkt=zh-CN")
	if err != nil {
		return "", fmt.Errorf("请求 Bing API 失败: %w", err)
	}
	defer resp.Body.Close()

	// 获取最终图片 URL（从 Location 头或响应体中）
	imageURL := ""
	if resp.StatusCode == 302 || resp.StatusCode == 301 || resp.StatusCode == 307 || resp.StatusCode == 308 {
		imageURL = resp.Header.Get("Location")
	} else if resp.StatusCode == 200 {
		// 有些 API 直接返回图片
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("读取响应失败: %w", err)
		}
		if err := os.WriteFile(cachePath, data, 0644); err != nil {
			return "", fmt.Errorf("缓存图片失败: %w", err)
		}
		return a.fileToDataURL(cachePath)
	}

	if imageURL == "" {
		return "", fmt.Errorf("未获取到图片地址，状态码: %d", resp.StatusCode)
	}

	// 下载实际图片
	imgResp, err := http.Get(imageURL)
	if err != nil {
		return "", fmt.Errorf("下载图片失败: %w", err)
	}
	defer imgResp.Body.Close()

	if imgResp.StatusCode != 200 {
		return "", fmt.Errorf("下载失败，状态码: %d", imgResp.StatusCode)
	}

	data, err := io.ReadAll(imgResp.Body)
	if err != nil {
		return "", fmt.Errorf("读取图片数据失败: %w", err)
	}

	// 缓存到本地
	if err := os.WriteFile(cachePath, data, 0644); err != nil {
		return "", fmt.Errorf("缓存图片失败: %w", err)
	}

	// 设置为当前背景
	a.SetBackgroundImage(cachePath)

	return a.fileToDataURL(cachePath)
}

// GetCachedBingImage 获取缓存的 Bing 图片（如果存在）
func (a *App) GetCachedBingImage() string {
	cachePath := filepath.Join(a.GetQGLDir(), "cache", "bing_daily.jpg")
	if !fileExists(cachePath) {
		return ""
	}
	url, _ := a.fileToDataURL(cachePath)
	return url
}

func (a *App) fileToDataURL(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	ext := strings.ToLower(filepath.Ext(path))
	mimeMap := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".bmp":  "image/bmp",
		".webp": "image/webp",
	}
	mimeType := mimeMap[ext]
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", mimeType, b64), nil
}
