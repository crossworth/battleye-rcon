package rcon

import (
	"testing"
)

func TestNewChecksum(t *testing.T) {
	if NewChecksum([]byte("test")) != 3632233996 {
		t.Fail()
	}

	expected := uint32(353074917)

	input := []byte{255, 0, 116, 101, 115, 116, 101, 101, 101, 101}

	if NewChecksum(input) != expected {
		t.Fatalf("wrong checksum, expected %d, got %d", expected, NewChecksum(input))
	}
}

func TestVerifyChecksum(t *testing.T) {
	if !VerifyChecksum([]byte("test"), 3632233996) {
		t.Fail()
	}
}
