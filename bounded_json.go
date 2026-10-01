package main

// bounded_json.go 统一"从外部 HTTP(S) 接口拉一个 JSON 元数据文件"的读取方式。
//
// 版本清单、版本 JSON、资产索引这些接口历史上各自手写：
//
//	resp, _ := client.Get(u)
//	body, _ := io.ReadAll(io.LimitReader(resp.Body, 上限))
//	json.Unmarshal(body, &v)
//
// 这种写法有几个共性问题：
//
//  1. LimitReader 只是"最多读 N 字节"，服务端真返回超过 N 时，前 N 字节
//     仍会被 json.Unmarshal——要么碰巧解析出一个被截断的对象静默采用，
//     要么报一个与"体积超限"无关的语法错误，调用方无法区分攻击与抖动；
//  2. 不校验 Content-Type：一个被劫持的镜像可以把 HTML 错误页 / 任意二进制
//     当 JSON 回给我们（Unser 失败时只表现为语法错误，没有安全事件）；
//  3. 5xx / 连接重置没有退避重试；
//  4. 没有 context，取消下载任务时正在进行的元数据请求仍然占着连接。
//
// fetchJSONBounded 把这些收口：HTTPS 强制、多读 1 字节判定超限（超限是
// fatal，绝不 Unmarshal 截断体）、媒体类型白名单、瞬时错误指数退避、
// 全程 context；关键拒绝写安全审计。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	errJSONFetchTooLarge     = errors.New("JSON 响应体积超过安全上限")
	errJSONFetchBadType      = errors.New("JSON 响应 Content-Type 不被允许")
	errJSONFetchNoLimit      = errors.New("拉取 JSON 必须指定正的体积上限")
	errJSONFetchNoSuccessful = errors.New("全部 JSON 源地址都获取失败")
)

const (
	jsonFetchDefaultAttempts = 3
	jsonFetchBufSize         = 64 * 1024
	jsonFetchBackoffBase     = 500 * time.Millisecond
	jsonFetchMaxContentType  = 256
)

// jsonFetchOptions 控制一次有界 JSON 拉取。
type jsonFetchOptions struct {
	MaxBytes        int64        // 必填：响应体硬上限，超出即 fatal
	Attempts        int          // 可空：<=0 取 jsonFetchDefaultAttempts
	UserAgent       string       // 可空：为空不覆盖 UA
	Client          *http.Client // 可空：为空用 safeHTTPClient()
	AllowMediaTypes []string     // 可空：非空时响应媒体类型必须命中其一（小写比较）
	SourceLabel     string       // 可空：审计日志中标识这份元数据的名字，如 "版本清单"
}

// parseMediaType 从 Content-Type 头取 media type（去掉 ;charset=...），
// 并对异常超长头做收口，防止审计日志被撑大。
func parseMediaType(header string) string {
	h := strings.TrimSpace(header)
	if len(h) > jsonFetchMaxContentType {
		h = h[:jsonFetchMaxContentType]
	}
	if i := strings.IndexByte(h, ';'); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

// mediaTypeAllowed 判断实际媒体类型是否命中白名单。白名单为空表示不校验。
func mediaTypeAllowed(actual string, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	for _, m := range allow {
		if actual == strings.ToLower(strings.TrimSpace(m)) {
			return true
		}
	}
	return false
}

// readBoundedBody 从 rc 最多读取 maxBytes+1 字节。
// 返回 errJSONFetchTooLarge 表示实际数据超过上限；调用方不得使用 data。
func readBoundedBody(rc io.Reader, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(rc, maxBytes+1)
	buf := make([]byte, 0, 256)
	chunk := make([]byte, jsonFetchBufSize)
	for {
		n, err := limited.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if int64(len(buf)) > maxBytes {
				return nil, errJSONFetchTooLarge
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// fetchJSONBounded 拉取单个 HTTPS URL 上的 JSON 并反序列化到 out。
// 网络错误 / 408 / 429 / 5xx / 读体中断按指数退避重试；协议错误、超限、
// 媒体类型不符、JSON 语法错误为 fatal 不重试。
func fetchJSONBounded(ctx context.Context, rawURL string, out any, opts jsonFetchOptions) error {
	if !isHTTPSURL(rawURL) {
		return fmt.Errorf("拒绝不安全的 JSON URL（非 HTTPS）: %s", rawURL)
	}
	if opts.MaxBytes <= 0 {
		return errJSONFetchNoLimit
	}
	attempts := opts.Attempts
	if attempts <= 0 {
		attempts = jsonFetchDefaultAttempts
	}
	client := opts.Client
	if client == nil {
		client = safeHTTPClient()
	}
	label := opts.SourceLabel
	if label == "" {
		label = "JSON 元数据"
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		fatal, err := attemptJSONFetch(ctx, client, rawURL, out, opts, label)
		if err == nil {
			return nil
		}
		lastErr = err
		if fatal || attempt == attempts {
			return err
		}
		backoff := jsonFetchBackoffBase << uint(attempt-1)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return lastErr
}

// attemptJSONFetch 是单次尝试。
func attemptJSONFetch(ctx context.Context, client *http.Client, rawURL string,
	out any, opts jsonFetchOptions, label string) (fatal bool, err error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return true, fmt.Errorf("创建请求失败 %s: %w", rawURL, err)
	}
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// DNS / 连接重置 / 超时属于瞬时错误。
		return false, fmt.Errorf("%s请求失败 %s: %w", label, rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusRequestTimeout ||
			resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode >= 500
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"bounded-json", fmt.Sprintf("%s源返回 HTTP %d: %s", label, resp.StatusCode, rawURL))
		if !retryable {
			return true, fmt.Errorf("%w: HTTP %d (%s)", errSecureDownloadStatus, resp.StatusCode, rawURL)
		}
		return false, fmt.Errorf("%w: HTTP %d (%s)", errSecureDownloadStatus, resp.StatusCode, rawURL)
	}

	// 声明体积超限：连 body 都不必读。
	if resp.ContentLength > opts.MaxBytes {
		recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
			"bounded-json",
			fmt.Sprintf("%s声明体积 %d 超过上限 %d: %s", label, resp.ContentLength, opts.MaxBytes, rawURL))
		return true, fmt.Errorf("%w: %s 声明 %d > %d",
			errJSONFetchTooLarge, label, resp.ContentLength, opts.MaxBytes)
	}

	media := parseMediaType(resp.Header.Get("Content-Type"))
	if media != "" && !mediaTypeAllowed(media, opts.AllowMediaTypes) {
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"bounded-json",
			fmt.Sprintf("%s返回了非 JSON 媒体类型 %q: %s", label, media, rawURL))
		return true, fmt.Errorf("%w: %s 实际类型 %q", errJSONFetchBadType, label, media)
	}

	body, err := readBoundedBody(resp.Body, opts.MaxBytes)
	if err != nil {
		if errors.Is(err, errJSONFetchTooLarge) {
			recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
				"bounded-json",
				fmt.Sprintf("%s实际体积超过上限 %d: %s", label, opts.MaxBytes, rawURL))
			return true, fmt.Errorf("%w: %s 实际上限 %d", errJSONFetchTooLarge, label, opts.MaxBytes)
		}
		// 读体中断通常是瞬时网络问题，允许重试。
		return false, fmt.Errorf("读取%s响应体失败: %w", label, err)
	}

	if err := json.Unmarshal(body, out); err != nil {
		// 语法错误是服务端实际给出的内容问题，重试同一个 URL 不会变好，
		// 按 fatal 处理，让调用方尽快尝试下一个镜像。
		return true, fmt.Errorf("解析%s失败: %w", label, err)
	}
	return false, nil
}

// fetchJSONFromMirrors 按顺序尝试多个镜像地址，任一成功即返回；全部失败时
// 返回 errJSONFetchNoSuccessful 并带上最后一个地址的错误。地址之间不做退避
// （它们是不同源，不是同一源的瞬时抖动），单个地址内部仍有重试。
func fetchJSONFromMirrors(ctx context.Context, urls []string, out any, opts jsonFetchOptions) error {
	var lastErr error
	for _, u := range urls {
		if err := fetchJSONBounded(ctx, u, out, opts); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errJSONFetchNoSuccessful
	}
	return fmt.Errorf("%w: %v", errJSONFetchNoSuccessful, lastErr)
}
