package rcon

import (
	"hash/crc32"
)

// NewChecksum creates a checksum for the bytes provided
func NewChecksum(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

// VerifyChecksum check if the bytes matches the checksum provided
func VerifyChecksum(data []byte, checksum uint32) bool {
	return NewChecksum(data) == checksum
}
