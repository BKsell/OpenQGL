package main

// e70limbucatalogguard.go —— 林布文字码位目录。
//
// 威胁模型：
//   林布文罕用且渲染依赖字体，机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T25ClassBlock   = "block"
	E70T25ClassWarn    = "warn"
	E70T25ClassAllow   = "allow"
	E70T25ClassUnknown = "unknown"
)

var E70T25Block = []string{
	"U+1900",
	"U+1901",
	"U+1902",
	"U+1903",
	"U+1904",
	"U+1905",
	"U+1906",
	"U+1907",
	"U+1908",
	"U+1909",
	"U+190A",
	"U+190B",
	"U+190C",
	"U+190D",
	"U+190E",
	"U+190F",
	"U+1910",
	"U+1911",
	"U+1912",
	"U+1913",
	"U+1914",
	"U+1915",
	"U+1916",
	"U+1917",
	"U+1918",
	"U+1919",
	"U+191A",
	"U+191B",
	"U+191C",
	"U+191D",
	"U+191E",
	"U+191F",
	"U+1920",
	"U+1921",
	"U+1922",
	"U+1923",
	"U+1924",
	"U+1925",
	"U+1926",
	"U+1927",
	"U+1928",
	"U+1929",
	"U+192A",
	"U+192B",
	"U+192C",
	"U+192D",
	"U+192E",
	"U+192F",
	"U+1930",
	"U+1931",
	"U+1932",
	"U+1933",
	"U+1934",
	"U+1935",
	"U+1936",
	"U+1937",
	"U+1938",
	"U+1939",
	"U+193A",
	"U+193B",
	"U+193C",
	"U+193D",
	"U+193E",
	"U+193F",
	"U+1940",
	"U+1941",
	"U+1942",
	"U+1943",
	"U+1944",
	"U+1945",
	"U+1946",
	"U+1947",
	"U+1948",
	"U+1949",
	"U+194A",
	"U+194B",
	"U+194C",
	"U+194D",
	"U+194E",
	"U+194F",
}

var E70T25Warn = []string{
}

var E70T25Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T25Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T25In(list []string, v string) bool {
	for _, x := range list { if E70T25Lower(x) == v { return true } }
	return false
}

// E70T25Classify 分类单个令牌。
func E70T25Classify(tok string) string {
	v := E70T25Lower(tok)
	switch {
	case E70T25In(E70T25Block, v): return E70T25ClassBlock
	case E70T25In(E70T25Warn, v): return E70T25ClassWarn
	case E70T25In(E70T25Allow, v): return E70T25ClassAllow
	default: return E70T25ClassUnknown
	}
}
