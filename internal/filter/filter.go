package filter

import (
	"regexp"
	"strings"

	"github.com/arya2004/fynewire/internal/model"
)

func ciMatch(expr, field string) bool {
	if expr == "" {
		return true
	}
	re, err := regexp.Compile("(?i)" + expr)
	if err != nil {
		return strings.Contains(strings.ToLower(field), strings.ToLower(expr))
	}
	return re.MatchString(field)
}

func Apply(pkts []model.Packet,
	proto, sip, dip, sport, dport, free string,
	limit int,
) []model.Packet {

	var out []model.Packet
	for _, p := range pkts {
		text := p.Summary + " " + p.Detail
		if !(ciMatch(proto, text) &&
			ciMatch(sip, p.Summary) &&
			ciMatch(dip, p.Summary) &&
			ciMatch(sport, text) &&
			ciMatch(dport, text) &&
			ciMatch(free, text)) {
			continue
		}
		out = append(out, p)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}
