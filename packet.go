package rcon

import (
	"hash/crc32"
)

var (
	crc32TablePolynomial = crc32.MakeTable(0xedb88320)
)

type PacketType byte

const (
	LoginPacket         = PacketType(0x00)
	CommandPacket       = PacketType(0x01)
	FragmentationPacket = PacketType(0x00)
	ServerMessagePacket = PacketType(0x02)
)

type PacketHeader struct {
	B     byte
	E     byte
	CRC32 []byte
	End   byte
}

type Packet struct {
	Header  PacketHeader
	Payload []byte
}

func makeHeader(crc32 []byte) PacketHeader {
	return PacketHeader{
		B:     'B',
		E:     'E',
		CRC32: crc32,
		End:   0xff,
	}
}

func makePacket(payload []byte) Packet {
	hash := crc32.New(crc32TablePolynomial)
	_, _ = hash.Write(payload)

	return Packet{
		Header:  makeHeader(hash.Sum(nil)[:]),
		Payload: payload,
	}
}
