// Package osinfo parses /etc/os-release into a flat map of lowercase keys.
package osinfo

import (
	"os"
	"strings"
)

// Get reads /etc/os-release and returns its key/value pairs with lowercase keys
// and surrounding quotes stripped. Returns an empty map if the file is missing
// or unreadable — callers handle that as "unknown OS".
func Get() map[string]string {
	out := make(map[string]string)
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"`)
		out[strings.ToLower(k)] = v
	}
	return out
}
