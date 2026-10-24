package main

// e69mongoliancatalogguard.go —— 蒙古文字码位目录。
//
// 威胁模型：
//   传统蒙古文竖排且带方向控制，与水平终端混排可重排显示，用于日志伪造，
//   结构化字段应拒绝。纯字符查表，不用正则。

const (
	E69T14ClassBlock   = "block"
	E69T14ClassWarn    = "warn"
	E69T14ClassAllow   = "allow"
	E69T14ClassUnknown = "unknown"
)

var E69T14Block = []string{
	"U+1800",
	"U+1801",
	"U+1802",
	"U+1803",
	"U+1804",
	"U+1805",
	"U+1806",
	"U+1807",
	"U+1808",
	"U+1809",
	"U+180A",
	"U+180B",
	"U+180C",
	"U+180D",
	"U+180E",
	"U+180F",
	"U+1810",
	"U+1811",
	"U+1812",
	"U+1813",
	"U+1814",
	"U+1815",
	"U+1816",
	"U+1817",
	"U+1818",
	"U+1819",
	"U+181A",
	"U+181B",
	"U+181C",
	"U+181D",
	"U+181E",
	"U+181F",
	"U+1820",
	"U+1821",
	"U+1822",
	"U+1823",
	"U+1824",
	"U+1825",
	"U+1826",
	"U+1827",
	"U+1828",
	"U+1829",
	"U+182A",
	"U+182B",
	"U+182C",
	"U+182D",
	"U+182E",
	"U+182F",
	"U+1830",
	"U+1831",
	"U+1832",
	"U+1833",
	"U+1834",
	"U+1835",
	"U+1836",
	"U+1837",
	"U+1838",
	"U+1839",
	"U+183A",
	"U+183B",
	"U+183C",
	"U+183D",
	"U+183E",
	"U+183F",
	"U+1840",
	"U+1841",
	"U+1842",
	"U+1843",
	"U+1844",
	"U+1845",
	"U+1846",
	"U+1847",
	"U+1848",
	"U+1849",
	"U+184A",
	"U+184B",
	"U+184C",
	"U+184D",
	"U+184E",
	"U+184F",
	"U+1850",
	"U+1851",
	"U+1852",
	"U+1853",
	"U+1854",
	"U+1855",
	"U+1856",
	"U+1857",
	"U+1858",
	"U+1859",
	"U+185A",
	"U+185B",
	"U+185C",
	"U+185D",
	"U+185E",
	"U+185F",
	"U+1860",
	"U+1861",
	"U+1862",
	"U+1863",
	"U+1864",
	"U+1865",
	"U+1866",
	"U+1867",
	"U+1868",
	"U+1869",
	"U+186A",
	"U+186B",
	"U+186C",
	"U+186D",
	"U+186E",
	"U+186F",
	"U+1870",
	"U+1871",
	"U+1872",
	"U+1873",
	"U+1874",
	"U+1875",
	"U+1876",
	"U+1877",
	"U+1878",
	"U+1879",
	"U+187A",
	"U+187B",
	"U+187C",
	"U+187D",
	"U+187E",
	"U+187F",
	"U+1880",
	"U+1881",
	"U+1882",
	"U+1883",
	"U+1884",
	"U+1885",
	"U+1886",
	"U+1887",
	"U+1888",
	"U+1889",
	"U+188A",
	"U+188B",
	"U+188C",
	"U+188D",
	"U+188E",
	"U+188F",
	"U+1890",
	"U+1891",
	"U+1892",
	"U+1893",
	"U+1894",
	"U+1895",
	"U+1896",
	"U+1897",
	"U+1898",
	"U+1899",
	"U+189A",
	"U+189B",
	"U+189C",
	"U+189D",
	"U+189E",
	"U+189F",
	"U+18A0",
	"U+18A1",
	"U+18A2",
	"U+18A3",
	"U+18A4",
	"U+18A5",
	"U+18A6",
	"U+18A7",
	"U+18A8",
	"U+18A9",
	"U+18AA",
	"U+18AB",
	"U+18AC",
	"U+18AD",
	"U+18AE",
	"U+18AF",
}

var E69T14Warn = []string{
}

var E69T14Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T14Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T14In(list []string, v string) bool {
	for _, x := range list { if E69T14Lower(x) == v { return true } }
	return false
}

// E69T14Classify 分类单个令牌。
func E69T14Classify(tok string) string {
	v := E69T14Lower(tok)
	switch {
	case E69T14In(E69T14Block, v): return E69T14ClassBlock
	case E69T14In(E69T14Warn, v): return E69T14ClassWarn
	case E69T14In(E69T14Allow, v): return E69T14ClassAllow
	default: return E69T14ClassUnknown
	}
}
