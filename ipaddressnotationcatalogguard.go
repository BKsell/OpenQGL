package main

// ipaddressnotationcatalogguard.go —— IP 地址异常记法目录。
//
// 威胁模型：
//   十进制/八进制/十六进制整数 IP、前导零、0 简写、IPv4-mapped IPv6 可绕过字符串黑名单。本目录收录异常记法，
//   纯字符查表，不用正则。

const (
	IPNClassBlock   = "block"
	IPNClassWarn    = "warn"
	IPNClassAllow   = "allow"
	IPNClassUnknown = "unknown"
)

var IPNBlock = []string{
	"2130706433",
	"3232235521",
	"0x7f000001",
	"0x7f.0.0.1",
	"0177.0.0.1",
	"017700000001",
	"0x7f.0x1",
	"0",
	"0.0.0",
	"0.0",
	"127.1",
	"127.0.1",
	"192.168.1",
	"10.1",
	"0:0:0:0:0:0:0:1",
	"::ffff:127.0.0.1",
	"::ffff:7f00:1",
	"::ffff:a9fe:a9fe",
	"127.0.0.1.",
	".127.0.0.1",
	"127.0.0.1:",
	"http://0",
	"http://0x7f000001",
	"http://2130706433",
	"http://017700000001",
	"0xc0.0xa8.0x01.0x01",
	"0300.0250.0001.0001",
	"[::ffff:7f00:1]",
	"[0:0:0:0:0:ffff:127.0.0.1]",
}

var IPNWarn = []string{
	"127.0.0.1",
	"localhost",
	"0.0.0.0",
	"10.0.0.0",
	"10.255.255.255",
	"172.16.0.0",
	"172.31.255.255",
	"192.168.0.0",
	"192.168.255.255",
	"169.254.0.0",
	"100.64.0.0",
	"::1",
	"fc00::",
	"fe80::",
	"192.0.2.0",
	"198.51.100.0",
	"203.0.113.0",
	"08.08.08.08",
	"192.168.01.1",
	"10.00.00.1",
	"[::1]",
	"[fc00::1]",
	"[fe80::1]",
}

var IPNAllow = []string{
	"8.8.8.8",
	"1.1.1.1",
	"9.9.9.9",
	"208.67.222.222",
	"114.114.114.114",
	"223.5.5.5",
	"180.76.76.76",
	"172.217.0.0",
	"142.250.0.0",
	"13.107.0.0",
	"2606:4700:4700::1111",
	"2001:4860:4860::8888",
}

func IPNLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func IPNIn(list []string, v string) bool {
	for _, x := range list { if IPNLower(x) == v { return true } }
	return false
}

// IPNClassify 分类单个令牌。
func IPNClassify(tok string) string {
	v := IPNLower(tok)
	switch {
	case IPNIn(IPNBlock, v): return IPNClassBlock
	case IPNIn(IPNWarn, v): return IPNClassWarn
	case IPNIn(IPNAllow, v): return IPNClassAllow
	default: return IPNClassUnknown
	}
}
