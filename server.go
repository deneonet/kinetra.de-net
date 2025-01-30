package knet

import (
	"crypto/ecdh"
	"crypto/sha256"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/deneonet/knet/cert"
	"github.com/deneonet/knet/crypto"
	"github.com/deneonet/knet/handshake"
	"github.com/deneonet/knet/netutils"

	bstd "github.com/deneonet/benc/std"
)

type Server struct {
	Addr                   string
	CertFile               string
	cert                   cert.ServerCertificate
	priv                   *ecdh.PrivateKey
	sessions               map[net.Conn]ServerSession
	mutex                  sync.RWMutex
	netUtilsSettings       netutils.NetUtilsSettings
	ReadDeadline           time.Duration
	WriteDeadline          time.Duration
	HandshakeReadDeadline  time.Duration
	HandshakeWriteDeadline time.Duration
	EnableConnPurge        bool
	ConnPurgeInterval      time.Duration
	MinSessionsBeforePurge int
	IdleTimeout            time.Duration
	BufferSize             int
	OnRead                 func(net.Conn, ReadInfo) AfterAction
	OnDisconnect           func(net.Conn)
	OnSecureConnect        func(net.Conn, ServerSession) AfterAction
	OnAcceptingError       func(error) bool
	OnConnectionError      func(net.Conn, error) AfterAction
}

type ServerSession struct {
	SharedSecret []byte
	LastActivity time.Time
	Data         map[string]interface{}
}

type ServerHandshakeResult byte

const (
	ServerContinueHandshake ServerHandshakeResult = iota
	ServerHandshakeComplete
	ServerHandshakeError
)

type connectionErrorResult byte

const (
	connectionErrorContinue connectionErrorResult = iota
	connectionErrorReturn
	connectionErrorMoveOn
)

func (s *Server) connectionPurge() {
	for {
		time.Sleep(s.ConnPurgeInterval)
		if len(s.sessions) < s.MinSessionsBeforePurge {
			continue
		}

		s.mutex.Lock()

		now := time.Now()
		for conn, session := range s.sessions {
			if now.Sub(session.LastActivity) > s.IdleTimeout {
				conn.Close()
				delete(s.sessions, conn)
			}
		}

		s.mutex.Unlock()
	}
}

func (s *Server) handleConnectionError(conn net.Conn, err error) connectionErrorResult {
	if err == nil {
		return connectionErrorMoveOn
	}

	action := s.OnConnectionError(conn, err)
	if action == Close {
		return connectionErrorReturn
	}

	return connectionErrorContinue
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
		size, err := netutils.ReadFromConn(conn, buf, &s.netUtilsSettings)

		if int(size) > len(buf) {
			if result := s.handleConnectionError(conn, ErrDataExceededBufferSize); result == connectionErrorReturn {
				return
			}
			continue
		}

		if err != nil && !handshakeComplete {
			if result := s.handleConnectionError(conn, err); result == connectionErrorReturn {
				return
			}
			continue
		}

		if !handshakeComplete {
			result, err := s.processHandshake(conn, buf[4:size])
			if err != nil {
				if result := s.handleConnectionError(conn, err); result == connectionErrorReturn {
					return
				}
				continue
			}

			if result == ServerContinueHandshake {
				continue
			}

			if result == ServerHandshakeComplete {
				handshakeComplete = true
				session, _ = s.GetSession(conn)

				s.netUtilsSettings.HandshakeCompleted = true

				if s.OnSecureConnect != nil && s.OnSecureConnect(conn, session) == Close {
					break
				}

				continue
			}
		}

		if err == io.EOF || size == 0 {
			if s.OnDisconnect != nil {
				s.OnDisconnect(conn)
			}
			return
		}

		if s.OnRead == nil {
			continue
		}

		var data []byte = nil
		if err == nil {
			encrypted := buf[4] == 1
			data = buf[5:size]
			if encrypted {
				data, err = crypto.Decrypt(session.SharedSecret, data)
			}
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
	packet, err := handshake.UnmarshalHandshakePacket(buf)
	if err != nil {
		return ServerHandshakeError, err
	}

	switch packet.Type {
	case handshake.PacketTypeCertificateRequest:
		if err = handshake.SendCertResponseHandshakePacket(conn, s.cert, &s.netUtilsSettings); err != nil {
			return ServerHandshakeError, err
		}
		return ServerContinueHandshake, nil
	case handshake.PacketTypeClientInformation:
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
			LastActivity: time.Now(),
			Data:         make(map[string]interface{}),
		})

		verification, err := crypto.Encrypt(aesSecret[:], []byte{1, 2, 3, 4})
		if err != nil {
			return ServerHandshakeError, err
		}

		if err := handshake.SendHandshakePacket(conn, handshake.PacketTypeServerVerification, verification, &s.netUtilsSettings); err != nil {
			return ServerHandshakeError, err
		}
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

	if s.EnableConnPurge {
		go s.connectionPurge()
	}

	certData, err := os.ReadFile(s.CertFile)
	if err != nil {
		return err
	}
	if err = s.cert.Unmarshal(certData); err != nil {
		return err
	}

	if s.priv, err = ecdh.P521().NewPrivateKey(s.cert.PrivateKey); err != nil {
		return err
	}

	if s.IdleTimeout == 0 {
		s.IdleTimeout = 30 * time.Minute
	}
	if s.ConnPurgeInterval == 0 {
		s.ConnPurgeInterval = 35 * time.Minute
	}

	if s.sessions == nil {
		s.sessions = make(map[net.Conn]ServerSession)
	}

	s.netUtilsSettings = netutils.NetUtilsSettings{
		HandshakeReadDeadline:  s.HandshakeReadDeadline,
		HandshakeWriteDeadline: s.HandshakeWriteDeadline,
		ReadDeadline:           s.ReadDeadline,
		WriteDeadline:          s.WriteDeadline,
	}

	if s.OnAcceptingError == nil {
		s.OnAcceptingError = func(err error) bool { return true }
	}
	if s.OnConnectionError == nil {
		s.OnConnectionError = func(conn net.Conn, err error) AfterAction { panic(conn.RemoteAddr().String() + ": " + err.Error()) }
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.OnAcceptingError(err) {
				return err
			}

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
	return netutils.SendToConn(conn, len(encrypted)+1, func(n int, buf []byte) { buf[n] = 1; copy(buf[n+1:], encrypted) }, &s.netUtilsSettings)
}

func (s *Server) SendUnsecure(conn net.Conn, b []byte) error {
	return netutils.SendToConn(conn, len(b)+1, func(n int, buf []byte) { buf[n] = 0; copy(buf[n+1:], b) }, &s.netUtilsSettings)
}

func (s *Server) UnmarshalPacket(buf []byte, f func(int, []byte) error) error {
	n, id, err := bstd.UnmarshalInt(0, buf)
	if err != nil {
		return err
	}
	return f(id, buf[n:])
}

func (s *Server) SendPacket(conn net.Conn, id int, p Packet) error {
	buf := make([]byte, p.Size()+bstd.SizeInt(id))
	n := bstd.MarshalInt(0, buf, id)
	p.Marshal(buf[n:])
	return s.Send(conn, buf)
}

func (s *Server) SendPacketUnsecure(conn net.Conn, id int, p Packet) error {
	buf := make([]byte, p.Size()+bstd.SizeInt(id))
	n := bstd.MarshalInt(0, buf, id)
	p.Marshal(buf[n:])
	return s.SendUnsecure(conn, buf)
}

func (s *Server) SendPacketToAll(id int, p Packet) error {
	buf := make([]byte, p.Size()+bstd.SizeInt(id))
	n := bstd.MarshalInt(0, buf, id)
	p.Marshal(buf[n:])
	return s.SendToAll(buf)
}

func (s *Server) SendPacketUnsecureToAll(conn net.Conn, id int, p Packet) error {
	buf := make([]byte, p.Size()+bstd.SizeInt(id))
	n := bstd.MarshalInt(0, buf, id)
	p.Marshal(buf[n:])
	return s.SendUnsecureToAll(buf)
}

func (s *Server) SendToAll(buf []byte) error {
	for conn := range s.sessions {
		if err := s.Send(conn, buf); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) SendUnsecureToAll(buf []byte) error {
	for conn := range s.sessions {
		if err := s.SendUnsecure(conn, buf); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) SendToAllExcept(buf []byte, conns ...net.Conn) error {
	for conn := range s.sessions {
		if slices.Contains(conns, conn) {
			continue
		}
		if err := s.Send(conn, buf); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) SendPacketToAllExcept(id int, p Packet, conns ...net.Conn) error {
	buf := make([]byte, p.Size()+bstd.SizeInt(id))
	n := bstd.MarshalInt(0, buf, id)
	p.Marshal(buf[n:])
	return s.SendToAllExcept(buf, conns...)
}

func (s *Server) GetSession(conn net.Conn) (ServerSession, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	ses, ok := s.sessions[conn]
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

func (s *Server) Get(conn net.Conn, key string) (interface{}, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	ses, ok := s.sessions[conn]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return ses.Data[key], nil
}

func (s *Server) Store(conn net.Conn, key string, value interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	ses, ok := s.sessions[conn]
	if !ok {
		return ErrSessionNotFound
	}
	ses.Data[key] = value
	s.sessions[conn] = ses
	return nil
}
