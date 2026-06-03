package llmproxy

import (
	"regexp"
	"sort"
)

type Match struct {
	Value     string
	FieldType string
	Start     int
	End       int
}

var detectorPatterns = []struct {
	fieldType string
	re        *regexp.Regexp
}{
	{"email", regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
	{"pan", regexp.MustCompile(`(?i)\b[A-Z]{5}[0-9]{4}[A-Z]\b`)},
	{"aadhaar", regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`)},
	{"card_number", regexp.MustCompile(`\b(?:\d[ -]?){15,16}\b`)},
	{"phone", regexp.MustCompile(`\b[6-9]\d{9}\b`)},
}

func DetectPII(text string) []Match {
	var all []Match
	for _, p := range detectorPatterns {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			all = append(all, Match{
				Value:     text[loc[0]:loc[1]],
				FieldType: p.fieldType,
				Start:     loc[0],
				End:       loc[1],
			})
		}
	}
	return selectNonOverlapping(all)
}

func selectNonOverlapping(matches []Match) []Match {
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Start != matches[j].Start {
			return matches[i].Start < matches[j].Start
		}
		return (matches[i].End - matches[i].Start) > (matches[j].End - matches[j].Start)
	})

	var selected []Match
	for _, m := range matches {
		if overlapsAny(m, selected) {
			continue
		}
		selected = append(selected, m)
	}
	return selected
}

func overlapsAny(m Match, selected []Match) bool {
	for _, s := range selected {
		if m.Start < s.End && s.Start < m.End {
			return true
		}
	}
	return false
}

func replaceMatches(text string, matches []Match, valueToToken map[string]string) string {
	if len(matches) == 0 {
		return text
	}

	sorted := append([]Match(nil), matches...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Start > sorted[j].Start
	})

	out := text
	for _, m := range sorted {
		token, ok := valueToToken[m.Value]
		if !ok {
			continue
		}
		out = out[:m.Start] + token + out[m.End:]
	}
	return out
}
