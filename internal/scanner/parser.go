package scanner

import (
	"encoding/json"
	"strings"
)

// ParseNDJSON parses newline-delimited JSON into a slice of the specified type.
// Usage:
//
//	var checks []ProwlerOCSFCheck
//	err := ParseNDJSON(raw, &checks)
func ParseNDJSON[T any](raw []byte, result *[]T) error {
	lines := strings.Split(string(raw), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var item T
		if err := json.Unmarshal([]byte(line), &item); err == nil {
			*result = append(*result, item)
		}
		// Silently skip malformed lines like the original code
	}

	return nil
}
