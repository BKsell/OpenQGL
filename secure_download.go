package main

// secure_download.go 把"从 Mojang / 第三方镜像下载文件"这件事统一收敛到一条
// 安全通道。历史上各处下载点各自手写 HTTP 请求 + io.Copy，存在几个共性缺口：
//
//  1. 只信 Content-Length：服务端不发声明长度（分块传输）时，体积上限只能靠
//     cappedReader 在落地后发现，半截文件已经写进了目标路径；
//  2. 直接 OpenFile 目标路径写入，中途失败 / 被杀进程会留下一个看起来"存在"
//     的残文件，可能被上层"文件已存在直接跳过"误命中；
//  3. 没有对响应体做流式摘要，sha256 校验要重新通读一遍磁盘文件；
//  4. 网络抖动 / 503 没有退避重试，一次失败整个安装流程中断。
//
// streamVerifiedDownload 一次性解决：先落同目录临时文件，流式同时计数与
// sha256 摘要，体积（声明 + 实际多读 1 字节）双重校验，成功 fsync 后原子
// rename；可校验期望 sha256；瞬时错误指数退避重试；关键失败进安全审计。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	errSecureDownloadTooLarge = errors.New("下载体积超过安全上限")
	errSecureDownloadBadHash  = errors.New("下载文件 sha256 校验失败")
	errSecureDownloadBadSize  = errors.New("下载文件实际体积与声明不符")
	errSecureDownloadStatus   = errors.New("下载返回了非成功状态码")
	errSecureDownloadNoLimit  = errors.New("安全下载必须指定正的体积上限")
)

const (
	secureDownloadDefaultAttempts = 3
	secureDownloadBufSize         = 64 * 1024
	secureDownloadBackoffBase     = 500 * time.Millisecond
)

// secureDownloadOptions 控制一次安全下载。
type secureDownloadOptions struct {
	MaxBytes       int64               // 必填：声明与实际体积的共同硬上限
	ExpectedSHA256 string              // 可空：非空时必须与流式摘要一致（小写十六进制）
	Attempts       int                 // 可空：<=0 时取 secureDownloadDefaultAttempts
	UserAgent      string              // 可空：为空则不覆盖
	Client         *http.Client        // 可空：为空用 safeHTTPClient()
	Progress       func(received, total int64) // 可空：每读到一批数据回调一次
}

// secureDownloadResult 是一次成功下载的回执。
type secureDownloadResult struct {
	Bytes    int64  // 实际落盘字节数
	SHA256   string // 实际流式 sha256（小写十六进制）
	Attempts int    // 实际使用的尝试次数（1 表示首次成功）
}

// streamVerifiedDownload 执行一次可校验、可重试、原子落盘的安全下载。
//
// 失败时目标路径不会留下残文件：数据始终写在同目录临时文件里，只有全部
// 校验通过并 fsync 后才 rename 到目标路径。
func streamVerifiedDownload(ctx context.Context, url, destPath string, opts secureDownloadOptions) (*secureDownloadResult, error) {
	if !isHTTPSURL(url) {
		return nil, fmt.Errorf("拒绝不安全的下载 URL（非 HTTPS）: %s", url)
	}
	if opts.MaxBytes <= 0 {
		return nil, errSecureDownloadNoLimit
	}
	attempts := opts.Attempts
	if attempts <= 0 {
		attempts = secureDownloadDefaultAttempts
	}
	client := opts.Client
	if client == nil {
		client = safeHTTPClient()
	}
	dir := filepath.Dir(destPath)
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	// 目标路径已被符号链接 / 特殊文件占据时拒绝：rename 会跟随替换普通文件，
	// 但先挡住异常路径，避免被诱导把文件写到重解析点上。
	if bad, err := isSymlinkOrSpecial(destPath); err != nil {
		return nil, fmt.Errorf("检查目标路径失败: %w", err)
	} else if bad {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"secure-download", "目标路径是符号链接或特殊文件，拒绝下载写入: "+destPath)
		return nil, fmt.Errorf("拒绝写入符号链接或非普通文件: %s", destPath)
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		res, fatal, err := attemptSecureDownload(ctx, client, url, destPath, opts)
		if err == nil {
			res.Attempts = attempt
			return res, nil
		}
		lastErr = err
		// fatal 表示重试没有意义（超限 / 哈希不符 / 4xx），直接返回。
		if fatal || attempt == attempts {
			return nil, err
		}
		backoff := secureDownloadBackoffBase << uint(attempt-1)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// attemptSecureDownload 是单次尝试。返回 fatal=true 表示错误不可重试。
func attemptSecureDownload(ctx context.Context, client *http.Client, url, destPath string,
	opts secureDownloadOptions) (res *secureDownloadResult, fatal bool, err error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, true, fmt.Errorf("创建请求失败 %s: %w", url, err)
	}
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		// 网络层错误（DNS / 连接重置 / 超时）视为瞬时错误，交给上层退避重试。
		return nil, false, fmt.Errorf("下载请求失败 %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusRequestTimeout ||
			resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode >= 500
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"secure-download",
			fmt.Sprintf("下载源返回 HTTP %d: %s", resp.StatusCode, url))
		if !retryable {
			return nil, true, fmt.Errorf("%w: HTTP %d (%s)", errSecureDownloadStatus, resp.StatusCode, url)
		}
		return nil, false, fmt.Errorf("%w: HTTP %d (%s)", errSecureDownloadStatus, resp.StatusCode, url)
	}

	// 声明体积超限：连响应体都不必读，直接拒绝（不可重试，服务端不会改口）。
	if resp.ContentLength > opts.MaxBytes {
		recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
			"secure-download",
			fmt.Sprintf("下载声明体积 %d 超过上限 %d: %s", resp.ContentLength, opts.MaxBytes, url))
		return nil, true, fmt.Errorf("%w: 声明体积 %d 超过上限 %d",
			errSecureDownloadTooLarge, resp.ContentLength, opts.MaxBytes)
	}

	// 临时文件必须与目标同目录，rename 才是同卷原子操作。
	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".dl-*")
	if err != nil {
		return nil, false, fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}
	if err := tmp.Chmod(privateFilePerm); err != nil {
		cleanup()
		return nil, false, fmt.Errorf("设置临时文件权限失败: %w", err)
	}

	hasher := sha256.New()
	// 多读 1 字节：正好读到上限之后还有数据，说明实际超限。
	reader := io.LimitReader(resp.Body, opts.MaxBytes+1)
	buf := make([]byte, secureDownloadBufSize)
	var written int64

loop:
	for {
		select {
		case <-ctx.Done():
			cleanup()
			return nil, false, ctx.Err()
		default:
		}
		n, rerr := reader.Read(buf)
		if n > 0 {
			if _, werr := tmp.Write(buf[:n]); werr != nil {
				cleanup()
				return nil, false, fmt.Errorf("写入临时文件失败: %w", werr)
			}
			hasher.Write(buf[:n])
			written += int64(n)
			if opts.Progress != nil {
				opts.Progress(written, resp.ContentLength)
			}
		}
		switch {
		case rerr == io.EOF:
			break loop
		case rerr != nil:
			cleanup()
			// 连接中断通常是瞬时错误，允许重试。
			return nil, false, fmt.Errorf("读取下载数据失败: %w", rerr)
		}
	}

	if written > opts.MaxBytes {
		cleanup()
		recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
			"secure-download",
			fmt.Sprintf("下载实际体积 %d 超过上限 %d: %s", written, opts.MaxBytes, url))
		return nil, true, fmt.Errorf("%w: 实际体积 %d 超过上限 %d",
			errSecureDownloadTooLarge, written, opts.MaxBytes)
	}

	// 声明长度与实际不一致（仅在传输层未透明解压时才可比，gzip 自动解压时
	// Go 会清掉 Content-Length）。短斤少两的文件交给重试，重试用尽再失败。
	if resp.ContentLength > 0 && !resp.Uncompressed && written != resp.ContentLength {
		cleanup()
		return nil, false, fmt.Errorf("%w: 声明 %d 实际 %d (%s)",
			errSecureDownloadBadSize, resp.ContentLength, written, url)
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if expected := strings.ToLower(strings.TrimSpace(opts.ExpectedSHA256)); expected != "" {
		if !constantTimeEqualLowerHex(actualSHA, expected) {
			cleanup()
			recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
				"secure-download",
				"下载文件 sha256 与期望值不符（期望值不记入日志）: "+url)
			return nil, true, fmt.Errorf("%w: %s", errSecureDownloadBadHash, url)
		}
	}

	if err := tmp.Sync(); err != nil {
		cleanup()
		return nil, false, fmt.Errorf("刷新临时文件到磁盘失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, false, fmt.Errorf("关闭临时文件失败: %w", err)
	}
	// 原子替换：此刻起目标路径要么是旧的完整文件，要么是新的完整文件，
	// 不存在半截状态。
	if err := os.Rename(tmpName, destPath); err != nil {
		os.Remove(tmpName)
		return nil, false, fmt.Errorf("原子替换目标文件失败: %w", err)
	}

	return &secureDownloadResult{Bytes: written, SHA256: actualSHA}, false, nil
}

// constantTimeEqualLowerHex 在两个等长小写十六进制串之间做常量时间比较，
// 长度不同时仍提前返回（长度不是秘密），避免 sha256 校验引入时序侧信道。
func constantTimeEqualLowerHex(actual, expected string) bool {
	if len(actual) != len(expected) {
		return false
	}
	var v byte
	for i := 0; i < len(actual); i++ {
		v |= actual[i] ^ expected[i]
	}
	return v == 0
}
