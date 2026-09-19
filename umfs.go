package main

import (
	"crypto/rand"
	"crypto/tls"
	"hash"
	"math/big"
	"net/http"
	"time"
)

var (
	umfsM   = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 521), big.NewInt(1))
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
	umfs128 = big.NewInt(128)
)

const umfsBlockSize = 8

// safeHTTPClient 创建安全的 HTTP 客户端
// 配置 30 秒超时，TLS 1.2 最低版本，防止资源耗尽和降级攻击
func safeHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

func umfsMod(x *big.Int) *big.Int {
	return new(big.Int).And(x, umfsM)
}

func umfsPow(x, e *big.Int) *big.Int {
	return new(big.Int).Exp(x, e, umfsM)
}

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
}

func NewUMFS(data []byte) *UMFS {
	u := &UMFS{
		r:        new(big.Int).Set(umfsIVR),
		c:        new(big.Int).Set(umfsIVC),
		totalLen: 0,
		dataPool: make([]*big.Int, 0),
	}
	if data != nil {
		u.Absorb(data)
	}
	return u
}

func (u *UMFS) Absorb(data []byte) *UMFS {
	u.totalLen += len(data)
	for i := 0; i < len(data); i += umfsBlockSize {
		end := i + umfsBlockSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		num := new(big.Int).SetBytes(chunk)
		u.dataPool = append(u.dataPool, num)
		u.r = tenthOrderMapping(new(big.Int).Xor(u.r, num))
		term := umfsMod(new(big.Int).Mul(umfsPow(num, umfs7), u.r))
		u.c = new(big.Int).Mod(new(big.Int).Add(new(big.Int).Xor(u.c, u.r), term), umfsM)
	}
	return u
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

	res := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Lsh(u.r, 128), u.c), umfsM)
	if bitn <= 0 || bitn > 521 {
		bitn = 256
	}
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bitn)), big.NewInt(1))
	res = new(big.Int).And(res, mask)
	hexLen := (bitn + 3) / 4
	return fmtSprintf(hexLen, res)
}

func (u *UMFS) Digest() []byte {
	hex := u.HexDigest(256)
	result := make([]byte, 0, len(hex)/2)
	for i := 0; i < len(hex); i += 2 {
		b := hexToByte(hex[i])<<4 | hexToByte(hex[i+1])
		result = append(result, b)
	}
	return result
}

func hexToByte(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 10
	}
	if c >= 'A' && c <= 'F' {
		return c - 'A' + 10
	}
	return 0
}

func fmtSprintf(hexLen int, x *big.Int) string {
	hex := x.Text(16)
	for len(hex) < hexLen {
		hex = "0" + hex
	}
	return hex
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
	h.umfs.Absorb(p)
	return len(p), nil
}

func (h *UMFSHash) Sum(in []byte) []byte {
	originalData := h.umfs.dataPool
	originalR := h.umfs.r
	originalC := h.umfs.c
	originalLen := h.umfs.totalLen

	result := h.umfs.Digest()

	h.umfs.dataPool = originalData
	h.umfs.r = originalR
	h.umfs.c = originalC
	h.umfs.totalLen = originalLen

	return append(in, result...)
}

func (h *UMFSHash) Reset() {
	h.umfs = NewUMFS(nil)
}

func (h *UMFSHash) Size() int       { return 32 }
func (h *UMFSHash) BlockSize() int  { return umfsBlockSize }

func generateUMFSToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return umfsHash(b)
	}
	return umfsHash(b)
}

// 编译时断言 UMFSHash 实现 hash.Hash 接口
var _ hash.Hash = (*UMFSHash)(nil)
