package rcon

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseHeader(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		checkSum := NewChecksum([]byte("test"))

		checkSumBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(checkSumBytes, checkSum)

		var input bytes.Buffer
		input.WriteString("BE")
		input.Write(checkSumBytes)
		input.WriteByte(0xff)

		ph, err := ParseHeader(&input)
		if err != nil {
			t.FailNow()
		}

		if ph.Checksum != checkSum {
			t.Fatalf("wrong checksum, expected %d, got %d", checkSum, ph.Checksum)
		}
	})

	t.Run("error on end header missing", func(t *testing.T) {
		checkSumBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(checkSumBytes, 100)

		var input bytes.Buffer
		input.WriteString("BE")
		input.Write(checkSumBytes)

		_, err := ParseHeader(&input)
		if err == nil {
			t.FailNow()
		}
	})

	t.Run("error on crc32 missing", func(t *testing.T) {
		var input bytes.Buffer
		input.WriteString("BE")
		input.WriteByte(0xff)

		_, err := ParseHeader(&input)
		if err == nil {
			t.FailNow()
		}
	})

	t.Run("error on magic missing", func(t *testing.T) {
		checkSum := NewChecksum([]byte("test"))

		checkSumBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(checkSumBytes, checkSum)

		var input bytes.Buffer

		_, err := ParseHeader(&input)
		if err == nil {
			t.FailNow()
		}
	})

	t.Run("error on magic mismatch", func(t *testing.T) {
		checkSum := NewChecksum([]byte("test"))

		checkSumBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(checkSumBytes, checkSum)

		var input bytes.Buffer
		input.WriteString("NO")
		input.Write(checkSumBytes)
		input.WriteByte(0xff)

		_, err := ParseHeader(&input)
		if err == nil {
			t.FailNow()
		}
	})
}
