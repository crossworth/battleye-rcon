package rcon

import (
	"strings"
)

func addressWithoutPort(addr string) string {
	parts := strings.Split(addr, ":")
	return parts[0]
}
