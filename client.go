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

	"github.com/deneonet/knet/cert"
	"github.com/deneonet/knet/crypto"
	"github.com/deneonet/knet/handshake"
	"github.com/deneonet/knet/netutils"

	bstd "github.com/deneonet/benc/std"
)

type Client struct {
	priv    *ecdh.PrivateKey
	session ClientSession

	rootKey     cert.ClientRootKey
	RootKeyFile string

	mutex *sync.Mutex

	netUtilsSettings netutils.NetUtilsSettings

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

func (c *Client) processHandshake(conn net.Conn, buf []byte) (ClientHandshakeResult, error) {
	packet, err := handshake.UnmarshalHandshakePacket(buf)
	if err != nil {
		return ClientHandshakeError, err
	}

	switch packet.Type {
	case handshake.PacketTypeCertificateResponse:
		var certificate cert.ServerCertificate
		if err := certificate.Unmarshal(packet.Payload); err != nil {
			return ClientHandshakeError, err
		}

		// TODO: Custom expiry
		serverPublicKey, err := cert.VerifyCertificate(certificate, c.rootKey, 0)
		if err != nil {
			return ClientHandshakeError, err
		}

		if err = handshake.SendHandshakePacket(conn, handshake.PacketTypeClientInformation, c.priv.PublicKey().Bytes(), &c.netUtilsSettings); err != nil {
			return ClientHandshakeError, err
		}

		sharedSecret, err := c.priv.ECDH(serverPublicKey)
		if err != nil {
			return ClientHandshakeError, err
		}

		aesSecret := sha256.Sum256(sharedSecret)
		c.mutex.Lock()
		c.session = ClientSession{
			Conn:         conn,
			SharedSecret: aesSecret[:],
		}
		c.mutex.Unlock()

		return ClientContinueHandshake, nil
	case handshake.PacketTypeServerVerification:
		if _, err := crypto.Decrypt(c.session.SharedSecret, packet.Payload); err != nil {
			return ClientHandshakeError, ErrDecryptingServerVerification
		}

		return ClientHandshakeComplete, nil
	}

	return ClientHandshakeError, ErrInvalidHandshakePacket
}

func (c *Client) Connect(address string) (net.Conn, error) {
	c.netUtilsSettings = netutils.NetUtilsSettings{
		HandshakeReadDeadline:  c.HandshakeReadDeadline,
		HandshakeWriteDeadline: c.HandshakeWriteDeadline,
		ReadDeadline:           c.ReadDeadline,
		WriteDeadline:          c.WriteDeadline,
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

	defer conn.Close()

	if err = handshake.SendHandshakePacket(conn, handshake.PacketTypeCertificateRequest, nil, &c.netUtilsSettings); err != nil {
		return nil, err
	}

	handshakeComplete := false
	buf := make([]byte, c.BufferSize)

	for {
		s, err := netutils.ReadFromConn(conn, buf, &c.netUtilsSettings)

		if err != nil && !handshakeComplete {
			return nil, err
		}

		var result ClientHandshakeResult
		if !handshakeComplete {
			result, err = c.processHandshake(conn, buf[4:s])
			if err != nil {
				conn.Close()
				return nil, err
			}

			if result == ClientContinueHandshake {
				continue
			}

			if result == ClientHandshakeComplete {
				handshakeComplete = true
				s = 0

				c.netUtilsSettings.HandshakeCompleted = true

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

	return conn, nil
}

func (c *Client) Send(b []byte) error {
	encrypted, err := crypto.Encrypt(c.session.SharedSecret, b)
	if err != nil {
		return err
	}
	return netutils.SendToConn(c.session.Conn, len(encrypted)+1, func(n int, b []byte) {
		b[n] = 1
		copy(b[n+1:], encrypted)
	}, &c.netUtilsSettings)
}

func (c *Client) SendUnsecure(b []byte) error {
	return netutils.SendToConn(c.session.Conn, len(b)+1, func(n int, buf []byte) {
		buf[n] = 0
		copy(buf[n+1:], b)
	}, &c.netUtilsSettings)
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
