package outbound

import "strings"

// redactWireGuardIpcConf hides secret key values before an IPC config is
// written to the debug trace log.
func redactWireGuardIpcConf(conf string) string {
	lines := strings.Split(conf, "\n")
	for i, line := range lines {
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "private_key", "preshared_key", "header_protection_key":
			lines[i] = key + "=<redacted>"
		}
	}
	return strings.Join(lines, "\n")
}
