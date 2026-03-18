package envutil

import (
	"os"
	"strings"
)

func ResolveOptional(value string, envName string) string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return trimmed
	}
	envName = strings.TrimSpace(envName)
	if envName == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(envName))
}
