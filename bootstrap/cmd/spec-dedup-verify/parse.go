package main

import (
	"fmt"
	"strings"
)

// ParseSameConceptResponse parses a raw Flash response to the
// same-concept template. Expected shape:
//   VERDICT: <yes|no|uncertain>
//   RATIONALE: <one sentence>
// Whitespace-tolerant; case-insensitive on VERDICT/RATIONALE labels and
// on the yes/no/uncertain tokens themselves.
func ParseSameConceptResponse(raw string) (verdict, rationale string, err error) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "VERDICT:") {
			v := strings.TrimSpace(trimmed[len("VERDICT:"):])
			v = strings.ToLower(v)
			switch v {
			case "yes", "no", "uncertain":
				verdict = v
			default:
				return "", "", fmt.Errorf("verdict token %q not in {yes,no,uncertain}", v)
			}
		} else if strings.HasPrefix(upper, "RATIONALE:") {
			rationale = strings.TrimSpace(trimmed[len("RATIONALE:"):])
		}
	}
	if verdict == "" {
		return "", "", fmt.Errorf("no VERDICT line in response")
	}
	return verdict, rationale, nil
}

// ParseCanonicalNameResponse parses a raw Flash response to the
// canonical-name-selection template. Expected shape:
//   NAME: <chosen_name>     or     NAME: PROPOSE: <new_name>
//   RATIONALE: <one sentence>
func ParseCanonicalNameResponse(raw string) (name, rationale string, proposed bool, err error) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "NAME:") {
			n := strings.TrimSpace(trimmed[len("NAME:"):])
			if strings.HasPrefix(strings.ToUpper(n), "PROPOSE:") {
				n = strings.TrimSpace(n[len("PROPOSE:"):])
				proposed = true
			}
			name = n
		} else if strings.HasPrefix(upper, "RATIONALE:") {
			rationale = strings.TrimSpace(trimmed[len("RATIONALE:"):])
		}
	}
	if name == "" {
		return "", "", false, fmt.Errorf("no NAME line in response")
	}
	return name, rationale, proposed, nil
}
