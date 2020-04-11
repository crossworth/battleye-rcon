package rcon

import (
	"net"
)

type Client interface {
	Close() error
	WriteTo(p []byte, addr net.Addr) (int, error)
}
