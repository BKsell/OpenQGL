package main

// guardreport：启动守卫汇总报告。
//
// 场景：多个 *guard 模块各自独立校验不同面（jarclass / worldmeta / launch /
// queue / instance / patch / natives / modmeta / crashreport），启动前需要
// 一份统一报告决定是否放行，以及把摘要写进审计日志。本模块只做聚合与
// 一行式文本化，不重复各模块逻辑，全部接受已算好的 verdict 结构。

import (
	"sort"
	"strings"
)

// guardSummary 单个守卫的摘要。
type guardSummary struct {
	Kind   string
	OK     bool
	Detail string
}

// startupGuardReport 启动前守卫聚合结果。
type startupGuardReport struct {
	OK      bool
	Blocked []string // 未通过守卫列表
	Lines   []string // 全部摘要行
}

// BuildStartupGuardReport 聚合守卫摘要。
func BuildStartupGuardReport(summaries []guardSummary) startupGuardReport {
	rep := startupGuardReport{OK: true}
	for _, s := range summaries {
		line := "[" + s.Kind + "] "
		if s.OK {
			line += "ok " + s.Detail
		} else {
			line += "BLOCKED " + s.Detail
			rep.Blocked = append(rep.Blocked, s.Kind)
		}
		rep.Lines = append(rep.Lines, line)
	}
	if len(rep.Blocked) > 0 {
		rep.OK = false
		sort.Strings(rep.Blocked)
	}
	return rep
}

// FlattenGuardReport 压成多行纯文本（每行一条）。
func FlattenGuardReport(rep startupGuardReport) string {
	if len(rep.Lines) == 0 {
		return "guards: none"
	}
	return strings.Join(rep.Lines, "\n")
}

// SummarizeGuardReport 压成一行。
func SummarizeGuardReport(rep startupGuardReport) string {
	if rep.OK {
		return "guards ok count=" + itoaSafe(len(rep.Lines))
	}
	return "guards blocked=" + strings.Join(rep.Blocked, ",")
}

// MarshalGuardReportJSON 输出可落盘的 JSON 形态（一行对象）。
func MarshalGuardReportJSON(rep startupGuardReport) string {
	var b strings.Builder
	b.WriteString(`{"ok":`)
	if rep.OK {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString(`,"blocked":[`)
	for i, k := range rep.Blocked {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("\"")
		b.WriteString(k)
		b.WriteString("\"")
	}
	b.WriteString(`],"lines":[`)
	for i, l := range rep.Lines {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("\"")
		b.WriteString(strings.ReplaceAll(l, "\"", "'"))
		b.WriteString("\"")
	}
	b.WriteString(`]}`)
	return b.String()
}

// GuardSummariesAll 一键生成常用守卫摘要（供启动闸门调用）。
func GuardSummariesAll(jarClass jarClassVerdict, launch launchVerdict, queue queueVerdict, world worldVerdict) []guardSummary {
	sum := []guardSummary{
		{Kind: "jarclass", OK: jarClass.OK, Detail: SummarizeJarClassVerdict(jarClass)},
		{Kind: "launch", OK: launch.OK, Detail: SummarizeLaunchVerdict(launch)},
		{Kind: "queue", OK: queue.OK, Detail: SummarizeQueueVerdict(queue)},
		{Kind: "world", OK: world.OK, Detail: SummarizeWorldVerdict(world)},
	}
	return sum
}
