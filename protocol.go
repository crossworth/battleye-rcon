package rcon

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// https://www.battleye.com/downloads/BERConProtocol.txt
// https://de.wikipedia.org/wiki/BattleEye_RCon_Protocol

const (
	validClientConnectionInterval = 50 * time.Second
)

type RCON struct {
	host             string
	port             int
	password         string
	commandHandler   func(command string, client Client)
	connectedClients sync.Map
	ipBanList        []string
}

type connectedClient struct {
	client   Client
	lastSeen time.Time
}

func NewRCON(host string, port int, password string) *RCON {
	return &RCON{host: host, port: port, password: password}
}

func (r *RCON) SetIPBanList(ipBanList []string) {
	r.ipBanList = ipBanList
}

func (r *RCON) OnCommand(handle func(command string, client Client)) {
	r.commandHandler = handle
}

func (r *RCON) addressInBanList(addr string) bool {
	for _, a := range r.ipBanList {
		if a == addr {
			return true
		}
	}

	return false
}

func (r *RCON) ListenAndServe() error {
	pc, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", r.host, r.port))
	if err != nil {
		return err
	}
	defer pc.Close()

	log.Printf("starting RCON server on port %d\n", r.port)

	for {
		buf := make([]byte, 1024)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("error reading packet, %v\n", err)
			continue
		}

		if r.addressInBanList(addressWithoutPort(addr.String())) {
			log.Printf("client %s present in the ip ban list, closing connection\n", addressWithoutPort(addr.String()))
			_ = pc.Close()
			continue
		}

		go r.handlePacket(pc, addr, buf[:n])
	}
}

func (r *RCON) removeInvalidClients() {
	r.connectedClients.Range(func(key, value interface{}) bool {
		cc := value.(connectedClient)

		if time.Now().Sub(cc.lastSeen) >= validClientConnectionInterval {
			log.Printf("removing client %s, invalid client connection interval\n", key)
			_ = cc.client.Close()
			r.connectedClients.Delete(key)
		}

		return true
	})
}

func (r *RCON) handlePacket(pc net.PacketConn, addr net.Addr, data []byte) {
	r.removeInvalidClients()

	_, present := r.connectedClients.Load(addr)
	if !present {
		log.Printf("client %s not logged", addr.String())
		_ = pc.Close()
		return
	}

	r.connectedClients.Store(addr, connectedClient{
		client:   pc,
		lastSeen: time.Now(),
	})


}

func addressWithoutPort(addr string) string {
	parts := strings.Split(addr, ":")
	return parts[0]
}
