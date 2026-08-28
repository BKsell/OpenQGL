package main

import (
	"math/big"
)

// UMFS (UltraMersenneFractalSponge) - 超梅森分形海绵哈希算法
// 从 bool-hybrid-array 项目移植，521位梅森素数模数

var (
	umfsM     = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 521), big.NewInt(1))
	umfsE1    = big.NewInt(11)
	umfsE2    = big.NewInt(13)
	umfsE3    = big.NewInt(17)
	umfsE4    = big.NewInt(19)
	umfsE5    = big.NewInt(23)
	umfsE6    = big.NewInt(29)
	umfsE7    = big.NewInt(31)
	umfsE8    = big.NewInt(37)
	umfsE9    = big.NewInt(41)
	umfsE10   = big.NewInt(43)
	umfsIVR   = big.NewInt(0x2957A2F168CC3509)
	umfsIVC   = big.NewInt(0x71D39E40BB72A61F)
	umfsC1    = big.NewInt(0x19260817)
	umfsC2    = big.NewInt(0x114514)
	umfsC3    = big.NewInt(0xABCDEF)
	umfsC4    = big.NewInt(0x233333)
	umfsC5    = big.NewInt(0x666666)
	umfsC6    = big.NewInt(0x123456789)
	umfs210   = big.NewInt(210)
	umfs7     = big.NewInt(7)
	umfs3     = big.NewInt(3)
	umfs128   = big.NewInt(128)
)

func umfsMod(x *big.Int) *big.Int {
	return new(big.Int).And(x, umfsM)
}

func umfsPow(x, e *big.Int) *big.Int {
	return new(big.Int).Exp(x, e, umfsM)
}

// tenthOrderMapping - 十阶模幂映射
func tenthOrderMapping(x *big.Int) *big.Int {
	// 第0阶: (pow(x,210) + pow(210,x) + pow(x,x) - 1) mod M
	p1 := umfsPow(x, umfs210)
	p2 := umfsPow(umfs210, x)
	p3 := umfsPow(x, x)
	x = umfsMod(new(big.Int).Sub(new(big.Int).Add(new(big.Int).Add(p1, p2), p3), big.NewInt(1)))

	// 第1阶: pow(x, E1) ^ C1
	x = new(big.Int).Xor(umfsPow(x, umfsE1), umfsC1)

	// 第2阶: (pow(x, E2) + C2) mod M
	x = umfsMod(new(big.Int).Add(umfsPow(x, umfsE2), umfsC2))

	// 第3阶: pow(x, E3) ^ (x>>18) ^ (x<<9)
	xShr := umfsMod(new(big.Int).Rsh(x, 18))
	xShl := umfsMod(new(big.Int).Lsh(x, 9))
	x = new(big.Int).Xor(new(big.Int).Xor(umfsPow(x, umfsE3), xShr), xShl)

	// 第4阶: (pow(x, E4) * C3) mod M
	x = umfsMod(new(big.Int).Mul(umfsPow(x, umfsE4), umfsC3))

	// 第5阶: pow(x, E5) ^ (x<<21)
	x = new(big.Int).Xor(umfsPow(x, umfsE5), umfsMod(new(big.Int).Lsh(x, 21)))

	// 第6阶: pow(x, E6) ^ C4
	x = new(big.Int).Xor(umfsPow(x, umfsE6), umfsC4)

	// 第7阶: (pow(x, E7) - C6) mod M
	x = umfsMod(new(big.Int).Sub(umfsPow(x, umfsE7), umfsC6))

	// 第8阶: pow(x, E8) ^ ((x>>12) & (x<<15))
	xS12 := umfsMod(new(big.Int).Rsh(x, 12))
	xS15 := umfsMod(new(big.Int).Lsh(x, 15))
	x = new(big.Int).Xor(umfsPow(x, umfsE8), new(big.Int).And(xS12, xS15))

	// 第9阶: (pow(x, E9) * C6) mod M
	x = umfsMod(new(big.Int).Mul(umfsPow(x, umfsE9), umfsC6))

	// 第10阶: pow(x, E10) ^ (x<<33)
	x = new(big.Int).Xor(umfsPow(x, umfsE10), umfsMod(new(big.Int).Lsh(x, 33)))

	return new(big.Int).Mod(x, umfsM)
}

// UMFS - 超梅森分形海绵哈希结构体
type UMFS struct {
	r        *big.Int
	c        *big.Int
	totalLen int
	dataPool []*big.Int
}

// NewUMFS - 创建新的 UMFS 实例
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

// Absorb - 吸收数据
func (u *UMFS) Absorb(data []byte) *UMFS {
	u.totalLen += len(data)
	step := len(data)
	if step < 8 {
		step = 8
	}
	for i := 0; i < len(data); i += step {
		end := i + step
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

// HexDigest - 输出十六进制哈希值
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
	format := "%0" + itoa(hexLen) + "x"
	return sprintf(format, res)
}

// Digest - 输出字节形式的哈希
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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func sprintf(format string, x *big.Int) string {
	// 简化版: 直接用 big.Int 的 Text 方法，然后补零
	hex := x.Text(16)
	// 从 format 中解析目标长度
	var targetLen int
	for i := 1; i < len(format); i++ {
		if format[i] >= '0' && format[i] <= '9' {
			targetLen = targetLen*10 + int(format[i]-'0')
		} else {
			break
		}
	}
	for len(hex) < targetLen {
		hex = "0" + hex
	}
	return hex
}

// umfsHash - 便捷函数，直接对数据进行 UMFS 哈希并返回十六进制字符串
func umfsHash(data []byte) string {
	return NewUMFS(data).HexDigest(256)
}
