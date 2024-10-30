package knet

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
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

type Client struct {
	priv    *ecdh.PrivateKey
	session ClientSession

	rootKey     cert.RootKey
	RootKeyFile string

	mutex *sync.Mutex

	ReadDeadline  time.Duration
	WriteDeadline time.Duration

	HandshakeReadDeadline  time.Duration
	HandshakeWriteDeadline time.Duration

	BufferSize int

	OnRead          func(net.Conn, ReadInfo) AfterAction
	OnDisconnect    func()
	OnSecureConnect func(ClientSession) AfterAction
}

type ClientSession struct {
	SharedSecret []byte
	Conn         net.Conn
}

type ClientHandshakeResult byte

const (
	ClientContinueHandshake ClientHandshakeResult = iota
	ClientHandshakeComplete
	ClientHandshakeError
)

func (c *Client) setDeadline(conn net.Conn, handshakeComplete bool) {
	conn.SetDeadline(time.Time{})

	var readDeadline, writeDeadline time.Duration
	if handshakeComplete {
		readDeadline, writeDeadline = c.ReadDeadline, c.WriteDeadline
	} else {
		readDeadline, writeDeadline = c.HandshakeReadDeadline, c.HandshakeWriteDeadline
	}

	if readDeadline > 0 {
		conn.SetReadDeadline(time.Now().Add(readDeadline))
	}
	if writeDeadline > 0 {
		conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	}
}

func (c *Client) processHandshake(conn net.Conn, buf []byte) (ClientHandshakeResult, error) {
	packet, err := packets.UnmarshalHandshakePacket(buf)
	if err != nil {
		return ClientHandshakeError, err
	}

	switch packets.HandshakePacketId(packet.Id) {
	case packets.CertificateResponse:
		var certificate cert.Certificate
		if err := certificate.Unmarshal(packet.Payload); err != nil {
			return ClientHandshakeError, err
		}

		serverPublicKey, err := cert.VerifyCertificate(certificate, c.rootKey)
		if err != nil {
			return ClientHandshakeError, err
		}

		if err = packets.SendHandshakePacket(conn, packets.ClientInformation, c.priv.PublicKey().Bytes()); err != nil {
			return ClientHandshakeError, err
		}

		sharedSecret, err := c.priv.ECDH(serverPublicKey)
		if err != nil {
			return ClientHandshakeError, err
		}

		aesSecret := sha256.Sum256(sharedSecret)
		c.session = ClientSession{
			Conn:         conn,
			SharedSecret: aesSecret[:],
		}

		return ClientContinueHandshake, nil
	case packets.ServerVerification:
		if _, err := crypto.Decrypt(c.session.SharedSecret, packet.Payload); err != nil {
			return ClientHandshakeError, ErrDecryptingVerificationId
		}

		return ClientHandshakeComplete, nil
	}

	return ClientHandshakeError, ErrInvalidHandshakePacket
}

func (c *Client) Connect(address string) (net.Conn, error) {
	if c.HandshakeReadDeadline == 0 {
		c.HandshakeReadDeadline = 500 * time.Millisecond
	}
	if c.HandshakeWriteDeadline == 0 {
		c.HandshakeWriteDeadline = 500 * time.Millisecond
	}

	c.mutex = &sync.Mutex{}

	bytes, err := os.ReadFile(c.RootKeyFile)
	if err != nil {
		return nil, err
	}

	if err = c.rootKey.Unmarshal(bytes); err != nil {
		return nil, err
	}
	if c.priv, err = ecdh.P521().GenerateKey(rand.Reader); err != nil {
		return nil, err
	}

	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}

	defer func() {
		conn.Close()
	}()

	if err = packets.SendHandshakePacket(conn, packets.CertificateRequest, nil); err != nil {
		return nil, err
	}

	handshakeComplete := false
	buf := make([]byte, c.BufferSize)

	for {
		c.setDeadline(conn, handshakeComplete)
		s, err := netutils.ReadFromConn(conn, buf)

		if err != nil && !handshakeComplete {
			return nil, err
		}

		var result ClientHandshakeResult
		if !handshakeComplete {
			result, err = c.processHandshake(conn, buf[4:s])
			if err != nil {
				return nil, err
			}

			if result == ClientContinueHandshake {
				continue
			}

			if result == ClientHandshakeComplete {
				handshakeComplete = true
				s = 0

				c.setDeadline(conn, handshakeComplete)
				if c.OnSecureConnect != nil {
					if action := c.OnSecureConnect(c.session); action == Close {
						break
					}
				}

				continue
			}
		}

		if err == io.EOF || s == 0 {
			if c.OnDisconnect != nil {
				c.OnDisconnect()
			}

			break
		}

		if c.OnRead == nil {
			continue
		}

		encrypted := buf[4] == 1
		data := buf[5:s]
		if encrypted && err == nil {
			data, err = crypto.Decrypt(c.session.SharedSecret, data)
		}

		action := c.OnRead(conn, ReadInfo{
			Err:  err,
			Data: data,
		})

		if action == Close {
			break
		}
	}

	return nil, err
}

func (c *Client) Send(b []byte) error {
	encrypted, err := crypto.Encrypt(c.session.SharedSecret, b)
	if err != nil {
		return err
	}
	return netutils.SendToConn(c.session.Conn, len(encrypted)+1, func(n int, b []byte) { b[n] = 1; copy(b[n+1:], encrypted) })
}

func (c *Client) SendUnsecure(b []byte) error {
	return netutils.SendToConn(c.session.Conn, len(b)+1, func(n int, buf []byte) { buf[n] = 0; copy(buf[n+1:], b) })
}

func (c *Client) SendPacket(id int, p Packet) error {
	b := make([]byte, p.Size()+bstd.SizeInt(id))
	n := bstd.MarshalInt(0, b, id)
	p.Marshal(b[n:])
	return c.Send(b)
}

func (c *Client) SendPacketUnsecure(id int, p Packet) error {
	b := make([]byte, p.Size()+bstd.SizeInt(id))
	n := bstd.MarshalInt(0, b, id)
	p.Marshal(b[n:])
	return c.SendUnsecure(b)
}

func (c *Client) UnmarshalPacket(b []byte, f func(int, []byte) error) error {
	n, id, err := bstd.UnmarshalInt(0, b)
	if err != nil {
		return err
	}
	return f(id, b[n:])
}

func (c *Client) GetConn() net.Conn {
	return c.session.Conn
}
