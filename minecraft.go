func (a *App) downloadFile(url string, destPath string, reportProgress bool) error {
	// 纵深防御：强制 HTTPS，即使调用方未校验也拒绝 HTTP 下载
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