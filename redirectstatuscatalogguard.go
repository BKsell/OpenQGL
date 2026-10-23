package main

// redirectstatuscatalogguard.go —— 重定向状态码语义目录。
//
// 威胁模型：
//   跟随重定向需区分临时/永久/特殊码：305 使用代理已废弃且危险，307/308 保留方法（对 POST 凭据敏感）。
//   本模块按整数状态码查目录，纯查表，不用正则。

const (
	RSCReasonBlock = "rsc-number-in-blocked-catalog"
	RSCReasonWarn  = "rsc-number-in-review-catalog"
	RSCReasonRange = "rsc-number-out-of-valid-range"
)

var RSCBlock = []int{
	300,305,306,
}

var RSCWarn = []int{
	301,302,303,
}

var RSCSafe = []int{
	307,308,
}

func RSCIn(list []int, v int) bool {
	for _, x := range list { if x == v { return true } }
	return false
}

type RSCFinding struct{ Reason string; Number int }
type RSCResult struct{ Safe bool; Findings []RSCFinding }
func RSCHas(r RSCResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

func RSCAudit(n int) RSCResult {
	res := RSCResult{Safe: true}
	if n < 100 || n > 599 { res.Safe=false; res.Findings=append(res.Findings,RSCFinding{Reason:RSCReasonRange,Number:n}); return res }
	switch {
	case RSCIn(RSCBlock, n): res.Findings=append(res.Findings,RSCFinding{Reason:RSCReasonBlock,Number:n})
	case RSCIn(RSCWarn, n): res.Findings=append(res.Findings,RSCFinding{Reason:RSCReasonWarn,Number:n})
	}
	if len(res.Findings)>0 { res.Safe=false }
	return res
}
