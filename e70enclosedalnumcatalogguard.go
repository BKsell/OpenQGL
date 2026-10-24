package main

// e70enclosedalnumcatalogguard.go —— 带圈字母数字码位目录。
//
// 威胁模型：
//   ① Ⓐ 等带圈字符与 ASCII 字母数字视觉近似，可绕过字符类别检查，
//   应 NFKC 归一化后判定。纯字符查表，不用正则。

const (
	E70T44ClassBlock   = "block"
	E70T44ClassWarn    = "warn"
	E70T44ClassAllow   = "allow"
	E70T44ClassUnknown = "unknown"
)

var E70T44Block = []string{
}

var E70T44Warn = []string{
	"U+2460",
	"U+2461",
	"U+2462",
	"U+2463",
	"U+2464",
	"U+2465",
	"U+2466",
	"U+2467",
	"U+2468",
	"U+2469",
	"U+246A",
	"U+246B",
	"U+246C",
	"U+246D",
	"U+246E",
	"U+246F",
	"U+2470",
	"U+2471",
	"U+2472",
	"U+2473",
	"U+2474",
	"U+2475",
	"U+2476",
	"U+2477",
	"U+2478",
	"U+2479",
	"U+247A",
	"U+247B",
	"U+247C",
	"U+247D",
	"U+247E",
	"U+247F",
	"U+2480",
	"U+2481",
	"U+2482",
	"U+2483",
	"U+2484",
	"U+2485",
	"U+2486",
	"U+2487",
	"U+2488",
	"U+2489",
	"U+248A",
	"U+248B",
	"U+248C",
	"U+248D",
	"U+248E",
	"U+248F",
	"U+2490",
	"U+2491",
	"U+2492",
	"U+2493",
	"U+2494",
	"U+2495",
	"U+2496",
	"U+2497",
	"U+2498",
	"U+2499",
	"U+249A",
	"U+249B",
	"U+249C",
	"U+249D",
	"U+249E",
	"U+249F",
	"U+24A0",
	"U+24A1",
	"U+24A2",
	"U+24A3",
	"U+24A4",
	"U+24A5",
	"U+24A6",
	"U+24A7",
	"U+24A8",
	"U+24A9",
	"U+24AA",
	"U+24AB",
	"U+24AC",
	"U+24AD",
	"U+24AE",
	"U+24AF",
	"U+24B0",
	"U+24B1",
	"U+24B2",
	"U+24B3",
	"U+24B4",
	"U+24B5",
	"U+24B6",
	"U+24B7",
	"U+24B8",
	"U+24B9",
	"U+24BA",
	"U+24BB",
	"U+24BC",
	"U+24BD",
	"U+24BE",
	"U+24BF",
	"U+24C0",
	"U+24C1",
	"U+24C2",
	"U+24C3",
	"U+24C4",
	"U+24C5",
	"U+24C6",
	"U+24C7",
	"U+24C8",
	"U+24C9",
	"U+24CA",
	"U+24CB",
	"U+24CC",
	"U+24CD",
	"U+24CE",
	"U+24CF",
	"U+24D0",
	"U+24D1",
	"U+24D2",
	"U+24D3",
	"U+24D4",
	"U+24D5",
	"U+24D6",
	"U+24D7",
	"U+24D8",
	"U+24D9",
	"U+24DA",
	"U+24DB",
	"U+24DC",
	"U+24DD",
	"U+24DE",
	"U+24DF",
	"U+24E0",
	"U+24E1",
	"U+24E2",
	"U+24E3",
	"U+24E4",
	"U+24E5",
	"U+24E6",
	"U+24E7",
	"U+24E8",
	"U+24E9",
	"U+24EA",
	"U+24EB",
	"U+24EC",
	"U+24ED",
	"U+24EE",
	"U+24EF",
	"U+24F0",
	"U+24F1",
	"U+24F2",
	"U+24F3",
	"U+24F4",
	"U+24F5",
	"U+24F6",
	"U+24F7",
	"U+24F8",
	"U+24F9",
	"U+24FA",
	"U+24FB",
	"U+24FC",
	"U+24FD",
	"U+24FE",
	"U+24FF",
}

var E70T44Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T44Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T44In(list []string, v string) bool {
	for _, x := range list { if E70T44Lower(x) == v { return true } }
	return false
}

// E70T44Classify 分类单个令牌。
func E70T44Classify(tok string) string {
	v := E70T44Lower(tok)
	switch {
	case E70T44In(E70T44Block, v): return E70T44ClassBlock
	case E70T44In(E70T44Warn, v): return E70T44ClassWarn
	case E70T44In(E70T44Allow, v): return E70T44ClassAllow
	default: return E70T44ClassUnknown
	}
}
