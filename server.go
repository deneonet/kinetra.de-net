package knet

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"kinetra.de/net/cert"
	"kinetra.de/net/crypto"
	"kinetra.de/net/netutils"
	"kinetra.de/net/packets"

	bstd "github.com/deneonet/benc/std"
)

type Server struct {
	// Addr is the address the server will bind to.
	Addr string

	// Cert is the file path to the server's certificate.
	CertFile string
	cert     cert.Certificate
	priv     *ecdh.PrivateKey

	sessions map[net.Conn]ServerSession

	mutex *sync.Mutex

	ReadDeadline  time.Duration
	WriteDeadline time.Duration

	HandshakeReadDeadline  time.Duration
	HandshakeWriteDeadline time.Duration

	EnableConnPurge   bool
	ConnPurgeInterval time.Duration

	IdleTimeout time.Duration
	BufferSize  int

	OnRead          func(net.Conn, ReadInfo) AfterAction
	OnDisconnect    func(net.Conn)
	OnSecureConnect func(net.Conn, ServerSession) AfterAction
}

type ServerSession struct {
	SharedSecret []byte
	// TODO: LastActivity time.Time
	// TODO: Data         map[string]interface{}
}

type ServerHandshakeResult byte

const (
	ServerContinueHandshake ServerHandshakeResult = iota
	ServerHandshakeComplete
	ServerHandshakeError
)

/*TOOD: func (s *Server) connectionPurge() {
	for {
		time.Sleep(s.ConnPurgeInterval)
		s.mutex.Lock()
		if proto.IsDebugMode() {
			fmt.Println("Start connection purge")
		}
		currentTime := time.Now()
		for conn, session := range s.ServerSessions {
			if currentTime.Sub(session.LastActivity) > s.IdleTimeout {
				// Connection has been idle for too long, close it.
				conn.Close()
				delete(s.ServerSessions, conn)
			}
		}
		if proto.IsDebugMode() {
			fmt.Println("Finished connection purge")
		}
		s.mutex.Unlock()
	}
}*/

func (s *Server) setDeadline(conn net.Conn, handshakeComplete bool) {
	conn.SetDeadline(time.Time{})

	var readDeadline, writeDeadline time.Duration
	if handshakeComplete {
		readDeadline, writeDeadline = s.ReadDeadline, s.WriteDeadline
	} else {
		readDeadline, writeDeadline = s.HandshakeReadDeadline, s.HandshakeWriteDeadline
	}

	if readDeadline > 0 {
		conn.SetReadDeadline(time.Now().Add(readDeadline))
	}
	if writeDeadline > 0 {
		conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		s.RemoveSession(conn)
	}()

	handshakeComplete := false
	buf := make([]byte, s.BufferSize)

	var session ServerSession
	for {
		s.setDeadline(conn, handshakeComplete)
		size, err := netutils.ReadFromConn(conn, buf)
		if int(size) > len(buf) {
			panic("data exceeded buffer size")
			break
		}

		if err != nil && !handshakeComplete {
			//TODO: error handling
			panic(err)
			break
		}

		var result ServerHandshakeResult
		if !handshakeComplete {
			result, err = s.processHandshake(conn, buf[4:size])
			if err != nil {
				//TODO: error handling
				panic(err)
				break
			}

			if result == ServerContinueHandshake {
				continue
			}

			if result == ServerHandshakeComplete {
				handshakeComplete = true
				size = 0

				session, _ = s.GetSession(conn)
				s.setDeadline(conn, handshakeComplete)

				if s.OnSecureConnect != nil {
					if action := s.OnSecureConnect(conn, session); action == Close {
						break
					}
				}

				continue
			}
		}

		if err == io.EOF || size == 0 {
			conn.Close()
			s.RemoveSession(conn)

			if s.OnDisconnect != nil {
				s.OnDisconnect(conn)
			}

			return
		}

		if s.OnRead == nil {
			continue
		}

		encrypted := buf[4] == 1
		data := buf[5:size]
		if encrypted && err == nil {
			data, err = crypto.Decrypt(session.SharedSecret, data)
		}

		action := s.OnRead(conn, ReadInfo{
			Err:  err,
			Data: data,
		})

		if action == Close {
			break
		}
	}
}

func (s *Server) processHandshake(conn net.Conn, buf []byte) (ServerHandshakeResult, error) {
	packet, err := packets.UnmarshalHandshakePacket(buf)
	if err != nil {
		return ServerHandshakeError, err
	}

	switch packets.HandshakePacketId(packet.Id) {
	case packets.CertificateRequest:
		if err = packets.SendCertResponseHandshakePacket(conn, packets.CertificateResponse, s.cert); err != nil {
			return ServerHandshakeError, err
		}

		return ServerContinueHandshake, nil
	case packets.ClientInformation:
		clientPublicKey, err := ecdh.P521().NewPublicKey(packet.Payload)
		if err != nil {
			return ServerHandshakeError, err
		}

		sharedSecret, err := s.priv.ECDH(clientPublicKey)
		if err != nil {
			return ServerHandshakeError, err
		}

		aesSecret := sha256.Sum256(sharedSecret)
		s.SetSession(conn, ServerSession{
			SharedSecret: aesSecret[:],
			// TODO: Data:         make(map[string]interface{}),
		})

		verification, err := crypto.Encrypt(aesSecret[:], []byte{1, 2, 3, 4})
		if err != nil {
			return ServerHandshakeError, err
		}

		packets.SendHandshakePacket(conn, packets.ServerVerification, verification)
		return ServerHandshakeComplete, nil
	}

	return ServerHandshakeError, ErrInvalidHandshakePacket
}

func (s *Server) Run() error {
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	//TODO: if s.EnableConnPurge {
	//	//go s.connectionPurge()
	//}
	bytes, err := os.ReadFile(s.CertFile)
	if err != nil {
		return err
	}
	if err = s.cert.Unmarshal(bytes); err != nil {
		return err
	}

	if s.priv, err = ecdh.P521().NewPrivateKey(s.cert.PrivateKey); err != nil {
		return err
	}

	if s.IdleTimeout == 0 {
		s.IdleTimeout = 30 * time.Minute
	}
	if s.sessions == nil {
		s.sessions = make(map[net.Conn]ServerSession)
	}

	if s.HandshakeReadDeadline == 0 {
		s.HandshakeReadDeadline = 500 * time.Millisecond
	}
	if s.HandshakeWriteDeadline == 0 {
		s.HandshakeWriteDeadline = 500 * time.Millisecond
	}

	s.mutex = &sync.Mutex{}

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) Send(conn net.Conn, b []byte) error {
	session, ok := s.GetSession(conn)
	if !ok {
		return ErrSessionNotFound
	}

	encrypted, err := crypto.Encrypt(session.SharedSecret, b)
	if err != nil {
		return err
	}
	return netutils.SendToConn(conn, len(encrypted)+1, func(n int, b []byte) { b[n] = 1; copy(b[n+1:], encrypted) })
}

func (s *Server) SendUnsecure(conn net.Conn, b []byte) error {
	return netutils.SendToConn(conn, len(b)+1, func(n int, buf []byte) { buf[n] = 0; copy(buf[n+1:], b) })
}

func (s *Server) UnmarshalPacket(b []byte, f func(int, []byte) error) error {
	n, id, err := bstd.UnmarshalInt(0, b)
	if err != nil {
		return err
	}
	return f(id, b[n:])
}

func (s *Server) SendPacket(conn net.Conn, id int, p Packet) error {
	b := make([]byte, p.Size()+bstd.SizeInt(id))
	n := bstd.MarshalInt(0, b, id)
	p.Marshal(b[n:])
	return s.Send(conn, b)
}

func (s *Server) SendPacketUnsecure(conn net.Conn, id int, p Packet) error {
	b := make([]byte, p.Size()+bstd.SizeInt(id))
	n := bstd.MarshalInt(0, b, id)
	p.Marshal(b[n:])
	return s.SendUnsecure(conn, b)
}

func (s *Server) SendPacketToAll(id int, p Packet) error {
	b := make([]byte, p.Size()+bstd.SizeInt(id))
	n := bstd.MarshalInt(0, b, id)
	p.Marshal(b[n:])
	return s.SendToAll(b)
}

func (s *Server) SendPacketUnsecureToAll(conn net.Conn, id int, p Packet) error {
	b := make([]byte, p.Size()+bstd.SizeInt(id))
	n := bstd.MarshalInt(0, b, id)
	p.Marshal(b[n:])
	return s.SendUnsecureToAll(b)
}

func (s *Server) SendToAll(b []byte) error {
	for conn := range s.sessions {
		if err := s.Send(conn, b); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) SendUnsecureToAll(b []byte) error {
	for conn := range s.sessions {
		if err := s.SendUnsecure(conn, b); err != nil {
			return err
		}
	}

	return nil
}

/*TODO:
func (s *Server) Store(conn gnet.Conn, key string, value interface{}) error {
	ses, ok := s.GetSession(conn)
	if !ok {
		return ErrSessionNotFound
	}

	s.mutex.Lock()
	ses.Data[key] = value
	s.mutex.Unlock()

	return nil
}

func (s *Server) Get(conn gnet.Conn, key string) (interface{}, error) {
	ses, ok := s.GetSession(conn)
	if !ok {
		return nil, ErrSessionNotFound
	}

	s.mutex.Lock()
	value := ses.Data[key]
	s.mutex.Unlock()

	return value, nil
}*/

func (s *Server) GetSession(conn net.Conn) (ServerSession, bool) {
	s.mutex.Lock()
	ses, ok := s.sessions[conn]
	s.mutex.Unlock()
	return ses, ok
}

func (s *Server) SetSession(conn net.Conn, session ServerSession) {
	s.mutex.Lock()
	s.sessions[conn] = session
	s.mutex.Unlock()
}

func (s *Server) RemoveSession(conn net.Conn) {
	s.mutex.Lock()
	delete(s.sessions, conn)
	s.mutex.Unlock()
}
