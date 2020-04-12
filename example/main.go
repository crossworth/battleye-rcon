package main

import (
	"fmt"
	"log"
	"net"

	rcon "github.com/crossworth/battleye-rcon"
)

func main() {
	server := rcon.NewRCON("", 2301, "test")

	server.OnCommand(func(seq uint8, command string, from net.Addr) {
		fmt.Println("command", command, seq, from.String())
		resp := rcon.MakeCommandResponsePacket(seq, []byte("echo "+command))
		server.SendResponse(from, resp)

		server.Broadcast(rcon.MakeServerMessagePacket(server.NextSequenceNumber(), []byte("GLOBAL: echo "+command)))
	})

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
