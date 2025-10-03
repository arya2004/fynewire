package model

import (
	"fmt"
	"regexp"
	"strings"
)

type Packet struct {
	Summary string
	Detail  string
}


func ciMatch(expr, field string) bool {
	if expr == "" {
		return true
	}
	re, err := regexp.Compile("(?i)" + expr) // case-insensitive
	if err != nil {
		return strings.Contains(strings.ToLower(field), strings.ToLower(expr))
	}
	return re.MatchString(field)
}

type FilterArgs struct {
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  string `json:"src_port"`
	DstPort  string `json:"dst_port"`
	FreeText string `json:"free_text"`
	Limit    int    `json:"limit"`
}

func ApplyFilters(pkts []Packet, f FilterArgs) []Packet {
	var out []Packet
	for _, p := range pkts {
		combined := p.Summary + " " + p.Detail
		if !(ciMatch(f.Protocol, combined) &&
			ciMatch(f.SrcIP, p.Summary) &&
			ciMatch(f.DstIP, p.Summary) &&
			ciMatch(f.SrcPort, combined) &&
			ciMatch(f.DstPort, combined) &&
			ciMatch(f.FreeText, combined)) {
			continue
		}
		out = append(out, p)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}

func FallbackFilter(prompt string) FilterArgs {
	return FilterArgs{FreeText: strings.ToLower(prompt)}
}

// Apply provides a convenience function with the same signature as filter.Apply for backward compatibility
func Apply(pkts []Packet, proto, sip, dip, sport, dport, free string, limit int) []Packet {
	return ApplyFilters(pkts, FilterArgs{
		Protocol: proto,
		SrcIP:    sip,
		DstIP:    dip,
		SrcPort:  sport,
		DstPort:  dport,
		FreeText: free,
		Limit:    limit,
	})
}

func (p Packet) String() string { return fmt.Sprintf("%s | %s", p.Summary, p.Detail) }
