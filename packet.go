package rcon

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
)

// PacketType defines possible packets types for the BattlEye RCon protocol
type PacketType byte

const (
	LoginPacketType         = PacketType(0x00) // LoginPacketType used during the login process
	CommandPacketType       = PacketType(0x01) // CommandPacketType used every time the client sends a packet
	ServerMessagePacketType = PacketType(0x02) // ServerMessagePacketType used when the server broadcast a packet for the client
	UnknownPacketType       = PacketType(0xff) // UnknownPacketType when the application cannot figure out the packet type

	FragmentationPacketType = PacketType(0x00) // FragmentationPacketType, a packet used when the server response has a lot of data, we dont implement it
)

// Stringer returns the string representation for the packet
func (p PacketType) Stringer() string {
	switch p {
	case LoginPacketType:
		return "LoginPacketType|FragmentationPacketType (0x00)"
	case CommandPacketType:
		return "CommandPacketType (0x01)"
	case ServerMessagePacketType:
		return "ServerMessagePacketType (0x02)"
	default:
		return "UnknownPacketType (0xff)"
	}
}

// LoginResponseType defines the possible login results
type LoginResponseType byte

const (
	LoginSuccessful = LoginResponseType(0x01) // LoginSuccessful when the password provided matches the password of the server
	LoginFailed     = LoginResponseType(0x00) // LoginFailed when the password is incorrect
)

var (
	packetHeaderMagic = []byte{'B', 'E'}
	packetHeaderEnd   = byte(0xff)
)

// PacketHeader defines a basic struct used on every packet
type PacketHeader struct {
	Magic    []byte // 2 byte magic, always BE
	Checksum uint32 // 4 bytes crc32 checksum of the following bytes (including the end)
	End      byte   // 1 byte, always 0xff
}

// NewPacketHeader creates a new packet with the checksum provided
func NewPacketHeader(checksum uint32) PacketHeader {
	return PacketHeader{
		Magic:    packetHeaderMagic,
		Checksum: checksum,
		End:      packetHeaderEnd,
	}
}

// Encode encodes the packet header in a byte slice representation
func (ph *PacketHeader) Encode() []byte {
	checkSumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(checkSumBytes, ph.Checksum)

	var output bytes.Buffer
	output.Write(ph.Magic)
	output.Write(checkSumBytes)
	output.WriteByte(ph.End)

	return output.Bytes()
}

// ParseHeader parse an input trying to "discovery" the needed data to decode the payload
func ParseHeader(input io.Reader) (PacketHeader, error) {
	var ph PacketHeader

	ph.Magic = make([]byte, 2)
	err := binary.Read(input, binary.LittleEndian, &ph.Magic)
	if err != nil {
		return ph, errors.Wrap(err, "could not read packet header magic")
	}

	if !bytes.Equal(ph.Magic, packetHeaderMagic) {
		return ph, errors.New("packet header magic mismatch")
	}

	err = binary.Read(input, binary.LittleEndian, &ph.Checksum)
	if err != nil {
		return ph, errors.Wrap(err, "could not read packet header Checksum")
	}

	err = binary.Read(input, binary.LittleEndian, &ph.End)
	if err != nil {
		return ph, errors.Wrap(err, "could not read packet header end")
	}

	if ph.End != packetHeaderEnd {
		return ph, errors.Wrap(err, "packet header end mismatch")
	}

	return ph, nil
}

// ParsePacketType tries to decode the packet type of the provided input
func ParsePacketType(input io.Reader) (PacketType, error) {
	var t byte
	err := binary.Read(input, binary.LittleEndian, &t)
	if err != nil {
		return UnknownPacketType, errors.Wrap(err, "could not decode packet type")
	}

	return PacketType(t), nil
}

// ParseSequenceNumber tries to decode the packet sequence number of the provided input
func ParseSequenceNumber(input io.Reader) (byte, error) {
	var seq byte
	err := binary.Read(input, binary.LittleEndian, &seq)
	if err != nil {
		return 0, errors.Wrap(err, "could not parse sequence number")
	}

	return seq, nil
}

// ParseCommand tries to read the rest of the input and extract an command or string
func ParseCommand(input io.Reader) (string, error) {
	buf := make([]byte, 4098)
	n, err := input.Read(buf)
	if err != nil {
		return "", errors.Wrap(err, "could not parse command")
	}

	return string(buf[0:n]), nil
}

// MakeLoginResponsePacket creates a new LoginResponsePacket already encoded as byte slice
func MakeLoginResponsePacket(responseType LoginResponseType) []byte {
	var payload bytes.Buffer
	payload.WriteByte(byte(LoginPacketType))
	payload.WriteByte(byte(responseType))

	header := NewPacketHeader(NewChecksum(append([]byte{0xff}, payload.Bytes()...)))

	var output bytes.Buffer
	output.Write(header.Encode())
	output.Write(payload.Bytes())

	return output.Bytes()
}

// MakeCommandResponsePacket creates a new CommandResponsePacket encoded as byte slice
// Note that you should provide the sequence number for the command that you are "answering"
// the data is the payload that you want to send
func MakeCommandResponsePacket(seq uint8, data []byte) []byte {
	var payload bytes.Buffer
	payload.WriteByte(byte(CommandPacketType))
	payload.WriteByte(byte(seq))

	if len(data) > 0 {
		payload.Write(data)
	}

	header := NewPacketHeader(NewChecksum(append([]byte{0xff}, payload.Bytes()...)))

	var output bytes.Buffer
	output.Write(header.Encode())
	output.Write(payload.Bytes())

	return output.Bytes()
}

// MakeServerMessagePacket creates a new ServerMessagePacket and encode it as a byte slice
// You must provide an sequence number, you can get an valid sequence number from the RCON struct
// calling the NextSequenceNumber, the data is the payload that you want to send
func MakeServerMessagePacket(seq uint8, data []byte) []byte {
	var payload bytes.Buffer
	payload.WriteByte(byte(ServerMessagePacketType))
	payload.WriteByte(byte(seq))

	if len(data) > 0 {
		payload.Write(data)
	}

	header := NewPacketHeader(NewChecksum(append([]byte{0xff}, payload.Bytes()...)))

	var output bytes.Buffer
	output.Write(header.Encode())
	output.Write(payload.Bytes())

	return output.Bytes()
}
