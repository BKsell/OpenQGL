package main

// portsrvccatalogguard.go —— 端口/服务敏感目录。
//
// 威胁模型：
//   SSRF 与本地绑定需识别目标端口敏感度：数据库、云管理、远程调试、SMB/RDP/Redis 等。本模块按整数端口
//   查目录并校验范围，纯查表，不发起连接，不用正则。

const (
	PSCReasonBlock = "psc-number-in-blocked-catalog"
	PSCReasonWarn  = "psc-number-in-review-catalog"
	PSCReasonRange = "psc-number-out-of-valid-range"
)

var PSCBlock = []int{
	22,23,25,111,135,137,138,139,445,1433,
	1521,2049,2375,2376,3306,3389,5432,5984,6379,8086,
	9200,9300,11211,27017,50070,5985,5986,4369,5672,15672,
	8161,9090,9418,4848,7001,7002,10250,10255,10259,6443,
	2379,2380,8500,8600,4646,3128,1080,
}

var PSCWarn = []int{
	80,21,990,143,993,110,995,587,465,389,
	636,8443,4000,8080,8888,3000,500,4500,8008,
}

var PSCSafe = []int{
	443,53,123,8000,9001,
}

func PSCIn(list []int, v int) bool {
	for _, x := range list { if x == v { return true } }
	return false
}

type PSCFinding struct{ Reason string; Number int }
type PSCResult struct{ Safe bool; Findings []PSCFinding }
func PSCHas(r PSCResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

func PSCAudit(n int) PSCResult {
	res := PSCResult{Safe: true}
	if n < 1 || n > 65535 { res.Safe=false; res.Findings=append(res.Findings,PSCFinding{Reason:PSCReasonRange,Number:n}); return res }
	switch {
	case PSCIn(PSCBlock, n): res.Findings=append(res.Findings,PSCFinding{Reason:PSCReasonBlock,Number:n})
	case PSCIn(PSCWarn, n): res.Findings=append(res.Findings,PSCFinding{Reason:PSCReasonWarn,Number:n})
	}
	if len(res.Findings)>0 { res.Safe=false }
	return res
}
