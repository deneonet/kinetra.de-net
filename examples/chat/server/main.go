package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	knet "kinetra.de/net"
	"kinetra.de/net/examples/chat/packets"
	"kinetra.de/net/examples/chat/packets/initialization"
	"kinetra.de/net/examples/chat/packets/message"
)

func main() {
	server := &knet.Server{
		Addr:                   "localhost:8080",
		CertFile:               "server.kc",
		EnableConnPurge:        true,
		ConnPurgeInterval:      10 * time.Minute,
		IdleTimeout:            30 * time.Minute,
		MinSessionsBeforePurge: 5,
		WriteDeadline:          10 * time.Second,
		BufferSize:             1024,
	}

	messages := make(map[uuid.UUID]packets.Message) // History of the messages
	usernames := make(map[string]bool)              // To track which username is still available (map as it's easier)

	messages[uuid.UUID{}] = packets.Message{}

	mutex := sync.RWMutex{}

	server.OnRead = func(conn net.Conn, info knet.ReadInfo) knet.AfterAction {
		err := server.UnmarshalPacket(info.Data, func(id int, b []byte) (err error) {
			switch id {
			case packets.InitializationUsernamePacket:
				var username initialization.Username
				if err = username.Unmarshal(b); err != nil {
					return
				}

				response := initialization.Response{
					Data: initialization.ResponseUsernameMissing,
				}

				if len(username.Data) == 0 {
					if err = server.SendPacket(conn, packets.InitializationResponsePacket, &response); err != nil {
						return
					}
					return nil
				}

				if _, ok := usernames[username.Data]; ok {
					response.Data = initialization.ResponseUsernameTaken
					if err = server.SendPacket(conn, packets.InitializationResponsePacket, &response); err != nil {
						return
					}
					return nil
				}

				response.Data = initialization.ResponseSuccess
				if err = server.SendPacket(conn, packets.InitializationResponsePacket, &response); err != nil {
					return
				}

				if err = server.Store(conn, "username", username.Data); err != nil {
					return
				}

				mutex.Lock()
				usernames[username.Data] = false
				mutex.Unlock()

				fmt.Printf("%s initialized as \"%s\".\n", conn.RemoteAddr().String(), username.Data)
				return nil
			case packets.MessagePacket:
				var message message.Packet
				if err = message.Unmarshal(b); err != nil {
					return
				}

				response := message.Response{
					Data: initialization.ResponseUsernameMissing,
				}

				if len(username.Data) == 0 {
					if err = server.SendPacket(conn, packets.InitializationResponsePacket, &response); err != nil {
						return
					}
					return nil
				}

				if _, ok := usernames[username.Data]; ok {
					response.Data = initialization.ResponseUsernameTaken
					if err = server.SendPacket(conn, packets.InitializationResponsePacket, &response); err != nil {
						return
					}
					return nil
				}

				response.Data = initialization.ResponseSuccess
				if err = server.SendPacket(conn, packets.InitializationResponsePacket, &response); err != nil {
					return
				}

				if err = server.Store(conn, "username", username.Data); err != nil {
					return
				}

				mutex.Lock()
				usernames[username.Data] = false
				mutex.Unlock()

				fmt.Printf("%s initialized as \"%s\".\n", conn.RemoteAddr().String(), username.Data)
				return nil
			}

			return nil
		})

		if err != nil {
			return knet.Close
		}

		return knet.None
	}

	server.OnSecureConnect = func(conn net.Conn, session knet.ServerSession) knet.AfterAction {
		fmt.Println("Established a secure connection with", conn.RemoteAddr().String())
		return knet.None
	}

	server.OnDisconnect = func(conn net.Conn) {
		username, err := server.Get(conn, "username")
		if err != nil {
			return
		}

		if username == nil {
			fmt.Printf("%s disconnected.\n", conn.RemoteAddr().String())
			return
		}

		fmt.Printf("%s disconnected.\n", username)

		mutex.Lock()
		delete(usernames, username.(string))
		mutex.Unlock()
	}

	server.OnConnectionError = func(conn net.Conn, err error) knet.AfterAction {
		fmt.Printf("Connection error: %s from %s\n", err, conn.RemoteAddr().String())
		return knet.Close
	}

	server.OnAcceptingError = func(err error) bool {
		fmt.Println("Server failed to accept a connection.")
		return false
	}

	err := server.Run()
	if err != nil {
		fmt.Println("Server error: ", err)
	}
}
