package main

// resumedlguard.go —— 大文件断点续传（HTTP Range）的一致性与防污染守卫。
//
// 威胁模型：
//   启动器下载 jre / mod / 整合包时支持断点续传：带 Range: bytes=start- 重连，
//   服务端可能返回 206 Partial Content + Content-Range，也可能无视 Range 直接
//   200 回整包。这里的真实风险不是“下不动”，而是“静默拼错”：
//     1. 镜像把 206 当 206 但 Content-Range 给错区间（start 偏移/越界），客户端
//        盲目追加，文件中段被错位数据覆盖，后续哈希校验前的解析器先崩或误执行；
//     2. 续传期间后端资源被替换（版本更新 / 投毒），ETag/Last-Modified 变化，
//        前半段是旧文件、后半段是新文件，拼成一个 polyglot；
//     3. 分片重叠 / 留缝 / 回退（start 比已写位置小），重复写入或产生空洞；
//     4. 恶意对端声明超大 total（Content-Range: */999999999999）诱导预分配巨文件，
//        磁盘耗尽（DoS）；
//     5. 第一次 200 全量、第二次却 206，或反之，状态机被对端牵着走。
//
// 本模块只做纯逻辑裁决：给定“请求区间 / 响应状态 / Content-Range / 校验器值 /
// 已写偏移”，决定接受、拒绝还是需要整包重来，不发请求、不碰文件系统。

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	errResumeBadRange       = errors.New("resume: 请求区间非法")
	errResumeStatusMismatch = errors.New("resume: 状态码与续传语义不符")
	errResumeTotalChanged   = errors.New("resume: 资源总长度变化，需整包重下")
	errResumeValidatorGone  = errors.New("resume: 校验标识(ETag)变化，资源已被替换")
	errResumeOverlap        = errors.New("resume: 分片与已写区间重叠")
	errResumeGap            = errors.New("resume: 分片起点与已写位置之间有空洞")
	errResumeRewind         = errors.New("resume: 分片起点回退")
	errResumeTotalTooLarge  = errors.New("resume: 声明总长度超限")
	errResumeContentRange   = errors.New("resume: Content-Range 无法解析")
	errResumeRangeMismatch  = errors.New("resume: Content-Range 区间与实际字节数不符")
)

// ResumeLimits 续传量化边界。
type ResumeLimits struct {
	MaxTotalBytes       int64 // 允许的资源总长度上限
	MaxSegmentBytes     int64 // 单片最大字节
	MinSegmentBytes     int64 // 单片最小字节（最后一片可更小，调用方区分）
	MaxSegments         int
	RequireStrongValidator bool // 是否强制 ETag 跨片一致（公网镜像建议开启）
}

func defaultResumeLimits() ResumeLimits {
	return ResumeLimits{
		MaxTotalBytes:          8 << 30, // 8GiB，覆盖最大整合包/JRE
		MaxSegmentBytes:        64 << 20,
		MinSegmentBytes:        1,
		MaxSegments:            20000,
		RequireStrongValidator: true,
	}
}

// ResumeSession 描述一次续传会话的累计状态。纯数据，调用方持久化。
type ResumeSession struct {
	Total        int64  // 首个响应确立的资源总长度，-1 表示未知（chunked）
	ETag         string // 首个响应的强校验标识
	LastModified string
	Written      int64 // 已连续写入的字节偏移（下一片必须从这里开始）
	Segments     int
	UsedResume   bool // 是否已经进入过 206 续传模式
	GotFull      bool // 是否收到过 200 全量
}

// ContentRange 是解析后的 Content-Range: bytes start-end/total。
type ContentRange struct {
	Start int64
	End   int64 // 含端点
	Total int64 // -1 表示 */ 未知总长度
}

// ParseContentRange 解析形如 "bytes 100-199/1000"、"bytes 100-199/*" 的值。
// 纯字符切分，不容忍前后缀噪声。
func ParseContentRange(value string) (ContentRange, error) {
	const prefix = "bytes "
	v := strings.TrimSpace(value)
	if !strings.HasPrefix(v, prefix) {
		return ContentRange{}, errResumeContentRange
	}
	v = v[len(prefix):]
	slash := strings.IndexByte(v, '/')
	if slash < 0 {
		return ContentRange{}, errResumeContentRange
	}
	rangePart, totalPart := v[:slash], v[slash+1:]
	dash := strings.IndexByte(rangePart, '-')
	if dash < 0 {
		return ContentRange{}, errResumeContentRange
	}
	start, err1 := strconv.ParseInt(rangePart[:dash], 10, 64)
	end, err2 := strconv.ParseInt(rangePart[dash+1:], 10, 64)
	if err1 != nil || err2 != nil || start < 0 || end < start {
		return ContentRange{}, errResumeContentRange
	}
	cr := ContentRange{Start: start, End: end, Total: -1}
	if totalPart != "*" {
		total, err := strconv.ParseInt(totalPart, 10, 64)
		if err != nil || total < 0 {
			return ContentRange{}, errResumeContentRange
		}
		cr.Total = total
	}
	return cr, nil
}

// ParseRangeRequest 解析客户端打算发送的 Range 请求值 "bytes=start-" /
// "bytes=start-end"，返回起止（无尾则 end=-1）。
func ParseRangeRequest(value string) (start, end int64, err error) {
	const prefix = "bytes="
	v := strings.TrimSpace(value)
	if !strings.HasPrefix(v, prefix) {
		return 0, 0, errResumeBadRange
	}
	v = v[len(prefix):]
	if strings.Contains(v, ",") {
		return 0, 0, errResumeBadRange // 本启动器不使用多区间
	}
	dash := strings.IndexByte(v, '-')
	if dash < 0 {
		return 0, 0, errResumeBadRange
	}
	s, err := strconv.ParseInt(v[:dash], 10, 64)
	if err != nil || s < 0 {
		return 0, 0, errResumeBadRange
	}
	if v[dash+1:] == "" {
		return s, -1, nil
	}
	e, err := strconv.ParseInt(v[dash+1:], 10, 64)
	if err != nil || e < s {
		return 0, 0, errResumeBadRange
	}
	return s, e, nil
}

// SegmentDecision 裁决结果。
type SegmentDecision struct {
	Accept       bool
	RestartFresh bool // 对端语义要求丢弃缓存、从 0 全量重下
	Reason       error
	WriteOffset  int64 // 本片应写入的起始偏移
	SegmentBytes int64
}

// JudgeSegment 裁决一次下载响应。
// 参数：
//   statusCode: 200 或 206；
//   reqStart/reqEnd: 本次请求发送的 Range（首次全量时 reqStart=0,reqEnd=-1 且 status=200）；
//   contentRange: 206 时的解析 Content-Range，200 时传零值；
//   bodyLen: 本片实际收到的字节数；
//   etag/lastMod: 本次响应头；
//   contentLength: 200 全量时的 Content-Length（-1 未知）。
func (s *ResumeSession) JudgeSegment(
	statusCode int,
	reqStart, reqEnd int64,
	cr ContentRange,
	bodyLen int64,
	etag, lastMod string,
	contentLength int64,
	lim ResumeLimits,
) SegmentDecision {
	if lim.MaxTotalBytes == 0 {
		lim = defaultResumeLimits()
	}

	// —— 200 全量响应 ——
	if statusCode == 200 {
		// 已经在续传模式里拼过一部分，对端却突然回 200：资源视图可能已变，
		// 必须整包重来，不能把全量当续传片追加。
		if s.UsedResume {
			return SegmentDecision{Accept: false, RestartFresh: true, Reason: errResumeStatusMismatch}
		}
		total := contentLength
		if total < 0 {
			total = bodyLen
		}
		if total > lim.MaxTotalBytes {
			return SegmentDecision{Accept: false, Reason: errResumeTotalTooLarge}
		}
		if bodyLen > lim.MaxSegmentBytes {
			return SegmentDecision{Accept: false, Reason: errResumeContentRange}
		}
		s.GotFull = true
		s.Written = bodyLen
		s.Segments = 1
		if total >= 0 {
			s.Total = total
		}
		s.ETag = normalizeValidator(etag)
		s.LastModified = lastMod
		return SegmentDecision{Accept: true, WriteOffset: 0, SegmentBytes: bodyLen}
	}

	// —— 206 续传响应 ——
	if statusCode != 206 {
		return SegmentDecision{Accept: false, Reason: fmt.Errorf("resume: 不支持的续传状态码 %d", statusCode)}
	}
	// 已经收过完整 200，就不应再有 206。
	if s.GotFull {
		return SegmentDecision{Accept: false, RestartFresh: true, Reason: errResumeStatusMismatch}
	}

	// Content-Range 必须与请求区间左边界严格一致。
	if cr.Start != reqStart {
		return SegmentDecision{Accept: false, RestartFresh: true, Reason: errResumeRewind}
	}
	if reqEnd >= 0 && cr.End != reqEnd && bodyLen != cr.End-cr.Start+1 {
		// 请求显式右边界时，服务端至少要自洽（允许正好在文件尾提前结束）。
		if cr.End > reqEnd {
			return SegmentDecision{Accept: false, Reason: errResumeRangeMismatch}
		}
	}

	// 总长度：首次确立，之后必须恒定。
	if cr.Total >= 0 {
		if cr.Total > lim.MaxTotalBytes {
			return SegmentDecision{Accept: false, Reason: errResumeTotalTooLarge}
		}
		if s.Total < 0 && s.Written == 0 {
			s.Total = cr.Total
		} else if s.Total >= 0 && cr.Total != s.Total {
			return SegmentDecision{Accept: false, RestartFresh: true, Reason: errResumeTotalChanged}
		}
	}

	// 强校验标识跨片一致（弱 ETag W/ 不保证字节一致，按缺失处理并据策略拒绝）。
	strong := normalizeValidator(etag)
	if strong != "" {
		if s.ETag == "" {
			s.ETag = strong
		} else if s.ETag != strong {
			return SegmentDecision{Accept: false, RestartFresh: true, Reason: errResumeValidatorGone}
		}
	} else if lim.RequireStrongValidator && s.ETag != "" {
		// 之前有强 ETag，这次消失，视为资源视图不可信。
		return SegmentDecision{Accept: false, RestartFresh: true, Reason: errResumeValidatorGone}
	}

	// 区间与已写位置衔接：不允许重叠、缝隙、回退。
	if cr.Start < s.Written {
		return SegmentDecision{Accept: false, Reason: errResumeOverlap}
	}
	if cr.Start > s.Written {
		return SegmentDecision{Accept: false, Reason: errResumeGap}
	}

	// 实际字节数必须自洽：bodyLen == end-start+1。
	want := cr.End - cr.Start + 1
	if bodyLen != want {
		return SegmentDecision{Accept: false, Reason: errResumeRangeMismatch}
	}
	if bodyLen > lim.MaxSegmentBytes {
		return SegmentDecision{Accept: false, Reason: errResumeContentRange}
	}
	if s.Total >= 0 && cr.End >= s.Total {
		return SegmentDecision{Accept: false, Reason: errResumeRangeMismatch}
	}
	s.Segments++
	if s.Segments > lim.MaxSegments {
		return SegmentDecision{Accept: false, Reason: fmt.Errorf("resume: 分片数超过上限 %d", lim.MaxSegments)}
	}

	s.UsedResume = true
	s.Written = cr.End + 1
	return SegmentDecision{Accept: true, WriteOffset: cr.Start, SegmentBytes: bodyLen}
}

// normalizeValidator 仅接受强 ETag（去掉 W/ 前缀后，弱标识返回空）。
func normalizeValidator(etag string) string {
	v := strings.TrimSpace(etag)
	if strings.HasPrefix(v, "W/") || strings.HasPrefix(v, "w/") {
		return ""
	}
	return v
}

// IsComplete 判断会话是否已收齐整个资源。
func (s *ResumeSession) IsComplete() bool {
	if s.Total < 0 {
		return s.GotFull // 未知总长度时只有 200 全量才算完整
	}
	return s.Written == s.Total
}

// NextRangeValue 生成下一次续传应发送的 Range 头值。
func (s *ResumeSession) NextRangeValue() string {
	return "bytes=" + strconv.FormatInt(s.Written, 10) + "-"
}
