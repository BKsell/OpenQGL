package main

import (
	"context"
	"path/filepath"
	"sync"
)

// App struct
type App struct {
	ctx              context.Context
	downloadProgress DownloadProgress
	downloadList     []DownloadItem
	downloadMutex    sync.Mutex
	isDownloading    bool
	downloadCancel   chan struct{}
	guestUnlocked    bool
	launchLogPath    string // 当前启动日志路径（版本目录下的 QGL\Logs）
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{
		downloadList:  make([]DownloadItem, 0),
		guestUnlocked: false,
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	// 安全事件审计日志固定放在 QGL/security 下（0700）。初始化失败不影响启动：
	// 审计器在未初始化状态下仍会把事件保存在内存环形缓冲里。
	auditDir := filepath.Join(a.GetQGLDir(), "security")
	_ = defaultSecurityAudit.initSecurityAudit(auditDir)
}
