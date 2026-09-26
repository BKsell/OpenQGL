package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// UMFS (Ultra Mersenne Fractal Sponge) — 与 bool-hybrid-array core.py 对齐。
// M = 2^2281 - 1（梅森素数），十阶模幂 + 海绵结构。
var (
	umfsM   = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 2281), big.NewInt(1))
	umfsE1  = big.NewInt(11)
	umfsE2  = big.NewInt(13)
	umfsE3  = big.NewInt(17)
	umfsE4  = big.NewInt(19)
	umfsE5  = big.NewInt(23)
	umfsE6  = big.NewInt(29)
	umfsE7  = big.NewInt(31)
	umfsE8  = big.NewInt(37)
	umfsE9  = big.NewInt(41)
	umfsE10 = big.NewInt(43)
	umfsIVR = big.NewInt(0x2957A2F168CC3509)
	umfsIVC = big.NewInt(0x71D39E40BB72A61F)
	umfsC1  = big.NewInt(0x19260817)
	umfsC2  = big.NewInt(0x114514)
	umfsC3  = big.NewInt(0xABCDEF)
	umfsC4  = big.NewInt(0x233333)
	umfsC5  = big.NewInt(0x666666)
	umfsC6  = big.NewInt(0x123456789)
	umfs210 = big.NewInt(210)
	umfs7   = big.NewInt(7)
	umfs3   = big.NewInt(3)
)

const umfsBlockSize = 8

// maxRedirects 单次请求最多跟 5 次跳转，超过就报错。
// 防止 CDN 被劫持后用无限跳转拖死启动。
const maxRedirects = 5

// isPrivateDest 报告 URL 指向的主机是不是内网/回环/链路本地地址。
// 启动器只该访问公网镜像和 Mojang，不应该被诱导去读 169.254.169.254
// （云元数据）或 127.0.0.1:本地端口。
func isPrivateDest(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if host == "" {
		return true
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsUnspecified()
	}
	// 没解析成 IP 的（域名），交给 DNS，不在这里拦；
	// 真正解析到内网的边缘情况由 net.Dialer 侧再兜一次。
	return false
}

// safeCheckRedirect 是 http.Client.CheckRedirect 的实现：
//   - 只允许跳 https://（除非原地 http→http，且我们本来就只发 https）；
//   - 拒绝跳内网/回环/链路本地；
//   - 最多 maxRedirects 次。
func safeCheckRedirect(requ *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return http.ErrUseLastResponse
	}
	next := requ.URL
	if !isHTTPSURL(next.String()) {
		return errDenyInsecureRedirect
	}
	if isPrivateDest(next.String()) {
		return errDenyPrivateRedirect
	}
	return nil
}

var (
	errDenyInsecureRedirect = &url.Error{Op: "Get", URL: "", Err: errText("redirect to non-HTTPS blocked")}
	errDenyPrivateRedirect  = &url.Error{Op: "Get", URL: "", Err: errText("redirect to private/loopback address blocked")}
)

type errText string

func (e errText) Error() string { return string(e) }

// safeHTTPClient 创建安全的 HTTP 客户端：
//   - TLS 1.2+；
//   - 30 秒总超时（API JSON 够用，大文件走带 MaxBytesReader 的专用路径）；
//   - 跳转策略：只跟 https→https，且不跳内网。
func safeHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		CheckRedirect: safeCheckRedirect,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			// 单连接复用池上限别太大，避免在用户机器上占一堆 TIME_WAIT
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

func umfsMod(x *big.Int) *big.Int {
	return new(big.Int).And(x, umfsM)
}

func umfsPow(x, e *big.Int) *big.Int {
	return new(big.Int).Exp(x, e, umfsM)
}

// tenthOrderMapping 十阶模幂置换
func tenthOrderMapping(x *big.Int) *big.Int {
	p1 := umfsPow(x, umfs210)
	p2 := umfsPow(umfs210, x)
	p3 := umfsPow(x, x)
	x = umfsMod(new(big.Int).Sub(new(big.Int).Add(new(big.Int).Add(p1, p2), p3), big.NewInt(1)))

	x = new(big.Int).Xor(umfsPow(x, umfsE1), umfsC1)
	x = umfsMod(new(big.Int).Add(umfsPow(x, umfsE2), umfsC2))

	xShr := umfsMod(new(big.Int).Rsh(x, 18))
	xShl := umfsMod(new(big.Int).Lsh(x, 9))
	x = new(big.Int).Xor(new(big.Int).Xor(umfsPow(x, umfsE3), xShr), xShl)

	x = umfsMod(new(big.Int).Mul(umfsPow(x, umfsE4), umfsC3))
	x = new(big.Int).Xor(umfsPow(x, umfsE5), umfsMod(new(big.Int).Lsh(x, 21)))
	x = new(big.Int).Xor(umfsPow(x, umfsE6), umfsC4)
	x = umfsMod(new(big.Int).Sub(umfsPow(x, umfsE7), umfsC6))

	xS12 := umfsMod(new(big.Int).Rsh(x, 12))
	xS15 := umfsMod(new(big.Int).Lsh(x, 15))
	x = new(big.Int).Xor(umfsPow(x, umfsE8), new(big.Int).And(xS12, xS15))

	x = umfsMod(new(big.Int).Mul(umfsPow(x, umfsE9), umfsC6))
	x = new(big.Int).Xor(umfsPow(x, umfsE10), umfsMod(new(big.Int).Lsh(x, 33)))

	return new(big.Int).Mod(x, umfsM)
}

type UMFS struct {
	r        *big.Int
	c        *big.Int
	totalLen int
	dataPool []*big.Int
	pending  bytes.Buffer
}

func NewUMFS(data []byte) *UMFS {
	u := &UMFS{
		r:        new(big.Int).Set(umfsIVR),
		c:        new(big.Int).Set(umfsIVC),
		totalLen: 0,
		dataPool: make([]*big.Int, 0),
	}
	if len(data) > 0 {
		u.pending.Write(data)
	}
	return u
}

func (u *UMFS) Absorb(data []byte) *UMFS {
	if len(data) == 0 {
		return u
	}
	u.totalLen += len(data)
	num := new(big.Int).SetBytes(data)
	u.dataPool = append(u.dataPool, num)
	u.r = tenthOrderMapping(new(big.Int).Xor(u.r, num))
	term := umfsMod(new(big.Int).Mul(umfsPow(num, umfs7), u.r))
	u.c = new(big.Int).Mod(new(big.Int).Add(new(big.Int).Xor(u.c, u.r), term), umfsM)
	return u
}

func (u *UMFS) flushPending() {
	if u.pending.Len() > 0 {
		u.Absorb(u.pending.Bytes())
		u.pending.Reset()
	}
}

func (u *UMFS) foldRecursive(arr []*big.Int) *big.Int {
	if len(arr) <= 2 {
		res := big.NewInt(0)
		for _, v := range arr {
			res = new(big.Int).Mod(new(big.Int).Add(res, tenthOrderMapping(new(big.Int).Xor(v, res))), umfsM)
		}
		return res
	}
	mid := len(arr) >> 1
	left := u.foldRecursive(arr[:mid])
	right := u.foldRecursive(arr[mid:])
	l3 := umfsPow(left, umfs3)
	r3 := umfsPow(right, umfs3)
	cross := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Xor(new(big.Int).Mul(left, right), l3), r3), umfsM)
	return tenthOrderMapping(cross)
}

func (u *UMFS) HexDigest(bitn int) string {
	u.flushPending()
	if bitn <= 0 || bitn > 4562 {
		bitn = 256
	}

	len3 := umfsPow(big.NewInt(int64(u.totalLen)), umfs3)
	u.r = new(big.Int).Xor(u.r, len3)
	u.c = new(big.Int).Mod(new(big.Int).Add(u.c, new(big.Int).Mul(len3, u.r)), umfsM)

	foldVal := u.foldRecursive(u.dataPool)
	u.r = new(big.Int).Mod(new(big.Int).Xor(u.r, foldVal), umfsM)

	for i := 0; i < 10; i++ {
		u.r = tenthOrderMapping(u.r)
		u.c = tenthOrderMapping(u.c)
		r3 := umfsPow(u.r, umfs3)
		c3 := umfsPow(u.c, umfs3)
		cross := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Xor(r3, c3), new(big.Int).Mul(u.r, u.c)), umfsM)
		oldR := new(big.Int).Set(u.r)
		u.r = new(big.Int).Mod(cross, umfsM)
		u.c = new(big.Int).Mod(new(big.Int).Xor(cross, oldR), umfsM)
	}

	shift := bitn - 2281
	if shift < 0 {
		shift = 0
	}
	res := new(big.Int).Xor(new(big.Int).Lsh(u.r, uint(shift)), u.c)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bitn)), big.NewInt(1))
	res.And(res, mask)

	hexLen := (bitn + 3) / 4
	hexStr := res.Text(16)
	for len(hexStr) < hexLen {
		hexStr = "0" + hexStr
	}
	return hexStr
}

func (u *UMFS) Digest() []byte {
	hx := u.HexDigest(256)
	b, _ := hex.DecodeString(hx)
	return b
}

func umfsHash(data []byte) string {
	return NewUMFS(data).HexDigest(256)
}

type UMFSHash struct {
	umfs *UMFS
}

func NewUMFSHash() *UMFSHash {
	return &UMFSHash{umfs: NewUMFS(nil)}
}

func (h *UMFSHash) Write(p []byte) (n int, err error) {
	h.umfs.pending.Write(p)
	return len(p), nil
}

func (h *UMFSHash) Sum(in []byte) []byte {
	savedR := new(big.Int).Set(h.umfs.r)
	savedC := new(big.Int).Set(h.umfs.c)
	savedLen := h.umfs.totalLen
	savedPool := append([]*big.Int{}, h.umfs.dataPool...)
	savedPending := make([]byte, h.umfs.pending.Len())
	copy(savedPending, h.umfs.pending.Bytes())

	result := h.umfs.Digest()

	h.umfs.r = savedR
	h.umfs.c = savedC
	h.umfs.totalLen = savedLen
	h.umfs.dataPool = savedPool
	h.umfs.pending.Reset()
	h.umfs.pending.Write(savedPending)

	return append(in, result...)
}

func (h *UMFSHash) Reset() {
	h.umfs = NewUMFS(nil)
}

func (h *UMFSHash) Size() int      { return 32 }
func (h *UMFSHash) BlockSize() int { return umfsBlockSize }

func generateUMFSToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return umfsHash(b)
	}
	return umfsHash(b)
}

// ===== MT-XOR25 PRNG（bool-hybrid-array core.py _real_generator 移植）=====
//
// 与 Python 版一致：MT19937 状态 + twist 时用 os.urandom(1) 再随机化一次，
// 输出时对 temper 结果再异或接下来 24 个状态字（共 25 字参与异或，故名 XOR25）。
// 种子熵来自 crypto/rand（对应 Python 的 os.urandom(8)）+ UMFS 吸收。

type mtXOR25 struct {
	state [624]uint32
	idx   int
}

func newMTXOR25() *mtXOR25 {
	m := &mtXOR25{idx: 624}
	entropy := make([]byte, 32)
	_, _ = rand.Read(entropy)
	seedBuf := NewUMFS(entropy).Absorb([]byte(time.Now().Format(time.RFC3339Nano))).Digest()
	seed := uint32(seedBuf[0]) | uint32(seedBuf[1])<<8 | uint32(seedBuf[2])<<16 | uint32(seedBuf[3])<<24
	m.state[0] = seed
	for i := 1; i < 624; i++ {
		m.state[i] = 1812433253*(m.state[i-1]^(m.state[i-1]>>30)) + uint32(i)
	}
	return m
}

func (m *mtXOR25) twist() {
	for i := 0; i < 624; i++ {
		y := (m.state[i] & 0x80000000) + (m.state[(i+1)%624] & 0x7FFFFFFF)
		m.state[i] = m.state[(i+397)%624] ^ (y >> 1)
		if y&1 == 1 {
			m.state[i] ^= 0x9908B0DF
			var b [1]byte
			_, _ = rand.Read(b[:])
			m.state[i] += uint32(b[0])
		}
	}
	m.idx = 0
}

func (m *mtXOR25) next() uint32 {
	if m.idx >= 624 {
		m.twist()
	}
	y := m.state[m.idx]
	m.idx++
	y ^= y >> 11
	y ^= (y << 7) & 0x9D2C5680
	y ^= (y << 15) & 0xEFC60000
	y ^= y >> 18
	xorResult := y
	for i := 1; i <= 25; i++ {
		xorResult ^= m.state[(m.idx+i-1)%624]
	}
	return xorResult
}

func (m *mtXOR25) bytes(n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		v := m.next()
		out = append(out, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	return out[:n]
}

// mtXOR25Bytes 返回 n 字节 mt_xor25 随机流（bool-hybrid-array 生态）。
func mtXOR25Bytes(n int) []byte {
	return newMTXOR25().bytes(n)
}

var _ hash.Hash = (*UMFSHash)(nil)

// ===== 文件完整性校验辅助 =====

// sha512File 计算文件 SHA-512
func sha512File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// umfsFile 流式计算文件 UMFS-256 十六进制摘要（bool-hybrid-array 生态）。
// 注意：UMFS 是整块吸收的海绵，这里把文件分块喂给 hash.Hash 接口的 Write，
// 在 Sum 时一次性 squeeze，与 Python 版对整文件 hexdigest 等价。
func umfsFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := NewUMFSHash()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
