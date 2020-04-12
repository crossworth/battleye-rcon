// Package RCON provides an implementation of the
// BattlEye RCon Protocol Specification v2 server side.
//
// It can be used to talk with RCON clients over a remote console
//
// Reference:
// https://www.battleye.com/downloads/BERConProtocol.txt
// https://de.wikipedia.org/wiki/BattleEye_RCon_Protocol
package rcon

import (
	"bytes"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"go.uber.org/atomic"
)

const (
	// interval in which the client has to send a command or packet,
	// the documentation talk about 45 seconds, we use 50 seconds to add a margin
	keepAliveCheck = 50 * time.Second

	// duration of brute-force-blocks
	// we block an ip after *loginTries* for this period of time
	blockIpInterval = 30 * time.Minute

	// max logins tries before the ip been blocked
	loginTries = 5

	// used for internal implementation
	rconServerMessageTries       = 5
	rconServerMessageRetryPeriod = 10 * time.Second
)

// RCON is the RCON server implementation
// it manages state about the clients, blocked and banned ips
// and server messages acknowledges.
type RCON struct {
	conn                      *net.UDPConn
	host                      string
	port                      int
	password                  string
	commandHandler            func(seq uint8, command string, from net.Addr)
	clients                   *cache.Cache
	blockedIp                 *cache.Cache
	wrongPasswordCounter      *cache.Cache
	ipBanList                 []string
	Logger                    Logger
	seqNumber                 atomic.Uint32
	serverMessageAcknowledges *cache.Cache
}

// NewRCON create a new RCON server with the host (IP/interface), port
// and password provided, it will not start the server.
func NewRCON(host string, port int, password string) *RCON {
	rcon := &RCON{
		host:                      host,
		port:                      port,
		password:                  password,
		clients:                   cache.New(cache.DefaultExpiration, 10*time.Minute),
		blockedIp:                 cache.New(cache.DefaultExpiration, 10*time.Minute),
		wrongPasswordCounter:      cache.New(cache.DefaultExpiration, 10*time.Minute),
		Logger:                    log.New(os.Stdout, "", log.LstdFlags),
		serverMessageAcknowledges: cache.New(cache.DefaultExpiration, 1*time.Minute),
	}

	rcon.seqNumber.Store(0)

	return rcon
}

// SetIPBanList defines the ip ban list to be used to avoid certain ips
func (r *RCON) SetIPBanList(ipBanList []string) {
	r.ipBanList = ipBanList
}

// OnCommand can be used to register a callback to be executed once the server receives a command
func (r *RCON) OnCommand(handle func(seq uint8, command string, from net.Addr)) {
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

// NextSequenceNumber returns the Next sequence number to be used on the
// MakeServerMessagePacket call
func (r *RCON) NextSequenceNumber() uint8 {
	number := r.seqNumber.Load()

	newNumber := r.seqNumber.Inc()

	if newNumber > 255 {
		r.seqNumber.Store(0)
	}

	return uint8(number)
}

func (r *RCON) addressInBlockedList(addr string) bool {
	for ip := range r.blockedIp.Items() {
		if ip == addr {
			return true
		}
	}

	return false
}

// Clients return an slice containing all the clients addresses authenticated
func (r *RCON) Clients() []net.Addr {
	var clients []net.Addr

	for _, c := range r.clients.Items() {
		clients = append(clients, c.Object.(net.Addr))
	}

	return clients
}

// Broadcast send an message to all the connected clients
// it will handle the retry and acknowledgement of messages
func (r *RCON) Broadcast(data []byte) {
	// we need the sequence, so we
	// have to parse the data first
	input := bytes.NewReader(data)
	_, _ = ParseHeader(input)
	_, _ = ParsePacketType(input)
	seq, _ := ParseSequenceNumber(input)

	for _, addr := range r.Clients() {
		go func(addr net.Addr, seq uint8) {

			receivedAcknowledge := false

			for i := 0; i < rconServerMessageTries; i++ {
				_ = r.SendResponse(addr, data)
				time.Sleep(time.Duration(rconServerMessageRetryPeriod.Seconds()/rconServerMessageTries) * time.Second)

				// check for acknowledge
				for addrAndSeq := range r.serverMessageAcknowledges.Items() {
					parts := strings.Split(addrAndSeq, "_")

					if parts[0] == addr.String() && strconv.Itoa(int(seq)) == parts[1] {
						receivedAcknowledge = true
						r.serverMessageAcknowledges.Delete(addrAndSeq)
					}
				}

				if receivedAcknowledge {
					break
				}
			}

			// could not write to client or received an acknowledge, remove it from list
			if !receivedAcknowledge {
				r.clients.Delete(addr.String())
			}
		}(addr, seq)
	}
}

// SendResponse sends an packet to a client
// The packet can be created using MakeCommandResponsePacket
// be aware that most of times you will only use this
// to send and response
func (r *RCON) SendResponse(to net.Addr, data []byte) error {
	_ = r.conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, err := r.conn.WriteTo(data, to)
	return err
}

// ListenAndServe start the server on the udp ip/port provided and
// start handling packets
func (r *RCON) ListenAndServe() error {
	udpAddr := net.UDPAddr{
		IP:   net.ParseIP(r.host),
		Port: r.port,
	}

	var err error
	r.conn, err = net.ListenUDP("udp", &udpAddr)
	if err != nil {
		return err
	}
	defer r.conn.Close()

	r.Logger.Printf("starting RCON server on port %d\n", r.port)

	for {
		buf := make([]byte, 4096)
		n, addr, err := r.conn.ReadFrom(buf)
		if err != nil {
			r.Logger.Printf("error reading packet, %v\n", err)
			continue
		}

		clientIP := addressWithoutPort(addr.String())

		if r.addressInBanList(clientIP) || r.addressInBlockedList(clientIP) {
			// we ignore the banned/blocked ip
			// since this protocol uses udp, the client cannot know if we are listening or ignoring
			continue
		}

		go r.handlePacket(addr, buf[:n])
	}
}

func (r *RCON) handlePacket(addr net.Addr, data []byte) {
	_, clientConnected := r.clients.Get(addr.String())

	input := bytes.NewReader(data)

	packetHeader, err := ParseHeader(input)
	if err != nil {
		r.Logger.Printf("%s: error reading packet header, %v\n", addr.String(), err)
		return
	}

	// we skip 6 bytes of packet header (the check sum uses the 0xff at the header)
	if !VerifyChecksum(data[6:], packetHeader.Checksum) {
		r.Logger.Printf("%s: wrong packet Checksum, expected %d, got %d\n", addr.String(), NewChecksum(data[6:]), packetHeader.Checksum)
		return
	}

	packetType, err := ParsePacketType(input)
	if err != nil {
		r.Logger.Printf("%s: error reading packet type, %v\n", addr.String(), err)
		return
	}

	if !clientConnected && packetType != LoginPacketType {
		r.Logger.Printf("%s: client trying to issue commands without authentication (%s), ignoring\n", addr.String(), packetType.Stringer())
		return
	}

	if !clientConnected && packetType == LoginPacketType {
		password, err := ParseCommand(input)
		if err != nil {
			r.Logger.Printf("%s: error reading password, %v\n", addr.String(), err)
			return
		}

		r.handleAuthentication(addr, password)
		return
	}

	// Refresh client keep alive
	r.clients.Set(addr.String(), addr, keepAliveCheck)

	if packetType == CommandPacketType {
		seq, err := ParseSequenceNumber(input)
		if err != nil {
			r.Logger.Printf("%s: error reading sequence number, %v\n", addr.String(), err)
			return
		}

		// we dont have anything else to read
		// so it must be a keepAlive packet
		if input.Len() == 0 {
			r.handleKeepAlive(addr, seq)
			return
		}

		// we have something to read, must be a command
		command, err := ParseCommand(input)
		if err != nil {
			r.Logger.Printf("%s: error reading command, %v\n", addr.String(), err)
			return
		}

		// if an command handler was defined we pass to it
		if r.commandHandler != nil {
			r.commandHandler(seq, command, addr)
			return
		}
	}

	if packetType == ServerMessagePacketType {
		seq, err := ParseSequenceNumber(input)
		if err != nil {
			r.Logger.Printf("%s: error reading sequence number of ServerMessagePacketType, %v\n", addr.String(), err)
			return
		}

		r.serverMessageAcknowledges.Set(addr.String()+"_"+strconv.Itoa(int(seq)), true, 15*time.Second)
		return
	}
}

func (r *RCON) handleKeepAlive(addr net.Addr, seq byte) {
	err := r.SendResponse(addr, MakeCommandResponsePacket(seq, []byte{}))
	if err != nil {
		r.Logger.Printf("%s: could not write to connection, %v\n", addr.String(), err)
	}
}

func (r *RCON) handleAuthentication(addr net.Addr, password string) {
	clientIP := addressWithoutPort(addr.String())

	if password != r.password {
		err := r.SendResponse(addr, MakeLoginResponsePacket(LoginFailed))

		if err != nil {
			r.Logger.Printf("%s: could not write to connection, %v\n", addr.String(), err)
		}

		_, found := r.wrongPasswordCounter.Get(clientIP)
		if !found {
			r.wrongPasswordCounter.Set(clientIP, 0, blockIpInterval)
		}

		times, _ := r.wrongPasswordCounter.IncrementInt(clientIP, 1)

		r.Logger.Printf("%s: wrong password provided (%s) - %d times\n", addr.String(), password, times)

		if times >= loginTries {
			r.blockedIp.Set(clientIP, true, blockIpInterval)
			r.Logger.Printf("%s: ip blocked for %s, reached maximum tries\n", addr.String(), blockIpInterval.String())
		}
	}

	log.Printf("%s: authenticated with password\n", addr.String())
	r.clients.Set(addr.String(), addr, keepAliveCheck)

	err := r.SendResponse(addr, MakeLoginResponsePacket(LoginSuccessful))
	if err != nil {
		r.Logger.Printf("%s: could not write to connection, %v\n", addr.String(), err)
	}
}
