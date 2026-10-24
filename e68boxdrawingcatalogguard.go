package main

// e68boxdrawingcatalogguard.go —— 制表符图形码位目录。
//
// 威胁模型：
//   制表符在等宽终端中可拼出伪造 UI 边框进行终端注入，
//   日志输出应按码点过滤。纯字符查表，不用正则。

const (
	E68R31ClassBlock   = "block"
	E68R31ClassWarn    = "warn"
	E68R31ClassAllow   = "allow"
	E68R31ClassUnknown = "unknown"
)

var E68R31Block = []string{
}

var E68R31Warn = []string{
	"U+2500",
	"U+2501",
	"U+2502",
	"U+2503",
	"U+2504",
	"U+2505",
	"U+2506",
	"U+2507",
	"U+2508",
	"U+2509",
	"U+250A",
	"U+250B",
	"U+250C",
	"U+250D",
	"U+250E",
	"U+250F",
	"U+2510",
	"U+2511",
	"U+2512",
	"U+2513",
	"U+2514",
	"U+2515",
	"U+2516",
	"U+2517",
	"U+2518",
	"U+2519",
	"U+251A",
	"U+251B",
	"U+251C",
	"U+251D",
	"U+251E",
	"U+251F",
	"U+2520",
	"U+2521",
	"U+2522",
	"U+2523",
	"U+2524",
	"U+2525",
	"U+2526",
	"U+2527",
	"U+2528",
	"U+2529",
	"U+252A",
	"U+252B",
	"U+252C",
	"U+252D",
	"U+252E",
	"U+252F",
	"U+2530",
	"U+2531",
	"U+2532",
	"U+2533",
	"U+2534",
	"U+2535",
	"U+2536",
	"U+2537",
	"U+2538",
	"U+2539",
	"U+253A",
	"U+253B",
	"U+253C",
	"U+253D",
	"U+253E",
	"U+253F",
	"U+2540",
	"U+2541",
	"U+2542",
	"U+2543",
	"U+2544",
	"U+2545",
	"U+2546",
	"U+2547",
	"U+2548",
	"U+2549",
	"U+254A",
	"U+254B",
	"U+254C",
	"U+254D",
	"U+254E",
	"U+254F",
	"U+2550",
	"U+2551",
	"U+2552",
	"U+2553",
	"U+2554",
	"U+2555",
	"U+2556",
	"U+2557",
	"U+2558",
	"U+2559",
	"U+255A",
	"U+255B",
	"U+255C",
	"U+255D",
	"U+255E",
	"U+255F",
	"U+2560",
	"U+2561",
	"U+2562",
	"U+2563",
	"U+2564",
	"U+2565",
	"U+2566",
	"U+2567",
	"U+2568",
	"U+2569",
	"U+256A",
	"U+256B",
	"U+256C",
	"U+256D",
	"U+256E",
	"U+256F",
	"U+2570",
	"U+2571",
	"U+2572",
	"U+2573",
	"U+2574",
	"U+2575",
	"U+2576",
	"U+2577",
	"U+2578",
	"U+2579",
	"U+257A",
	"U+257B",
	"U+257C",
	"U+257D",
	"U+257E",
	"U+257F",
}

var E68R31Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R31Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R31In(list []string, v string) bool {
	for _, x := range list { if E68R31Lower(x) == v { return true } }
	return false
}

// E68R31Classify 分类单个令牌。
func E68R31Classify(tok string) string {
	v := E68R31Lower(tok)
	switch {
	case E68R31In(E68R31Block, v): return E68R31ClassBlock
	case E68R31In(E68R31Warn, v): return E68R31ClassWarn
	case E68R31In(E68R31Allow, v): return E68R31ClassAllow
	default: return E68R31ClassUnknown
	}
}
