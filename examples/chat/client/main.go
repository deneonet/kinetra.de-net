package main

import (
	"errors"
	"fmt"
	"net"
	"time"

	knet "kinetra.de/net"
	"kinetra.de/net/examples/chat/packets"
	"kinetra.de/net/examples/chat/packets/initialization"
)

var ErrResponse = errors.New("response error")

func main() {
	client := &knet.Client{
		RootKeyFile:            "client.kr",
		BufferSize:             1024,
		WriteDeadline:          10 * time.Second,
		HandshakeReadDeadline:  500 * time.Millisecond,
		HandshakeWriteDeadline: 500 * time.Millisecond,
	}

	client.OnRead = func(conn net.Conn, info knet.ReadInfo) knet.AfterAction {
		err := client.UnmarshalPacket(info.Data, func(id int, b []byte) (err error) {
			switch id {
			case packets.InitializationResponsePacket:
				var response initialization.Response
				if err = response.Unmarshal(b); err != nil {
					return
				}

				switch response.Data {
				case initialization.ResponseUsernameTaken:
					fmt.Println("Username is taken.")
				case initialization.ResponseUsernameMissing:
					fmt.Println("Username is missing.")
				case initialization.ResponseSuccess:
					return nil
				}

				return ErrResponse
			}

			return nil
		})

		if err != nil {
			return knet.Close
		}

		return knet.None
	}

	client.OnSecureConnect = func(session knet.ClientSession) knet.AfterAction {
		fmt.Println("Secure connection established.")

		username := initialization.Username{
			Data: "deneonet",
		}
		err := client.SendPacket(packets.InitializationUsernamePacket, &username)
		if err != nil {
			fmt.Println("Error sending username packet: ", err)
		}

		return knet.None
	}

	client.OnDisconnect = func() {
		fmt.Println("Disconnected from server.")
	}

	_, err := client.Connect("localhost:8080")
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
}
