## BattlEye RCon Server Protocol v2

Implementation of the [RCON protocol](https://www.battleye.com/downloads/BERConProtocol.txt) for servers.

This project implements the server protocol without the `fragmentation/multiple packets` part.

It will handle the client state and brute-force attacks.

You can download an BattlEye RCon client at [https://www.battleye.com/downloads/](https://www.battleye.com/downloads/).

**Example simple UDP server**
```go
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
```


**Server**
![Server](/example/server.jpg)

**Client**
![Client](/example/client.jpg)
