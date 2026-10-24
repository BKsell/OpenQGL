package main

// e70myanmarcatalogguard.go —— 缅甸文字码位目录。
//
// 威胁模型：
//   缅甸文连写与重排规则复杂，可用于日志伪造与隐藏数据，
//   结构化字段应拒绝。纯字符查表，不用正则。

const (
	E70T22ClassBlock   = "block"
	E70T22ClassWarn    = "warn"
	E70T22ClassAllow   = "allow"
	E70T22ClassUnknown = "unknown"
)

var E70T22Block = []string{
	"U+1000",
	"U+1001",
	"U+1002",
	"U+1003",
	"U+1004",
	"U+1005",
	"U+1006",
	"U+1007",
	"U+1008",
	"U+1009",
	"U+100A",
	"U+100B",
	"U+100C",
	"U+100D",
	"U+100E",
	"U+100F",
	"U+1010",
	"U+1011",
	"U+1012",
	"U+1013",
	"U+1014",
	"U+1015",
	"U+1016",
	"U+1017",
	"U+1018",
	"U+1019",
	"U+101A",
	"U+101B",
	"U+101C",
	"U+101D",
	"U+101E",
	"U+101F",
	"U+1020",
	"U+1021",
	"U+1022",
	"U+1023",
	"U+1024",
	"U+1025",
	"U+1026",
	"U+1027",
	"U+1028",
	"U+1029",
	"U+102A",
	"U+102B",
	"U+102C",
	"U+102D",
	"U+102E",
	"U+102F",
	"U+1030",
	"U+1031",
	"U+1032",
	"U+1033",
	"U+1034",
	"U+1035",
	"U+1036",
	"U+1037",
	"U+1038",
	"U+1039",
	"U+103A",
	"U+103B",
	"U+103C",
	"U+103D",
	"U+103E",
	"U+103F",
	"U+1040",
	"U+1041",
	"U+1042",
	"U+1043",
	"U+1044",
	"U+1045",
	"U+1046",
	"U+1047",
	"U+1048",
	"U+1049",
	"U+104A",
	"U+104B",
	"U+104C",
	"U+104D",
	"U+104E",
	"U+104F",
	"U+1050",
	"U+1051",
	"U+1052",
	"U+1053",
	"U+1054",
	"U+1055",
	"U+1056",
	"U+1057",
	"U+1058",
	"U+1059",
	"U+105A",
	"U+105B",
	"U+105C",
	"U+105D",
	"U+105E",
	"U+105F",
	"U+1060",
	"U+1061",
	"U+1062",
	"U+1063",
	"U+1064",
	"U+1065",
	"U+1066",
	"U+1067",
	"U+1068",
	"U+1069",
	"U+106A",
	"U+106B",
	"U+106C",
	"U+106D",
	"U+106E",
	"U+106F",
	"U+1070",
	"U+1071",
	"U+1072",
	"U+1073",
	"U+1074",
	"U+1075",
	"U+1076",
	"U+1077",
	"U+1078",
	"U+1079",
	"U+107A",
	"U+107B",
	"U+107C",
	"U+107D",
	"U+107E",
	"U+107F",
	"U+1080",
	"U+1081",
	"U+1082",
	"U+1083",
	"U+1084",
	"U+1085",
	"U+1086",
	"U+1087",
	"U+1088",
	"U+1089",
	"U+108A",
	"U+108B",
	"U+108C",
	"U+108D",
	"U+108E",
	"U+108F",
	"U+1090",
	"U+1091",
	"U+1092",
	"U+1093",
	"U+1094",
	"U+1095",
	"U+1096",
	"U+1097",
	"U+1098",
	"U+1099",
	"U+109A",
	"U+109B",
	"U+109C",
	"U+109D",
	"U+109E",
	"U+109F",
}

var E70T22Warn = []string{
}

var E70T22Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T22Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T22In(list []string, v string) bool {
	for _, x := range list { if E70T22Lower(x) == v { return true } }
	return false
}

// E70T22Classify 分类单个令牌。
func E70T22Classify(tok string) string {
	v := E70T22Lower(tok)
	switch {
	case E70T22In(E70T22Block, v): return E70T22ClassBlock
	case E70T22In(E70T22Warn, v): return E70T22ClassWarn
	case E70T22In(E70T22Allow, v): return E70T22ClassAllow
	default: return E70T22ClassUnknown
	}
}
