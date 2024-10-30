//go:generate bencgen --in ../schemas/Handshake.benc --out . --file handshake.benc --lang go
package packets

import (
	"net"

	"kinetra.de/net/cert"
	"kinetra.de/net/netutils"
)

type HandshakePacketId byte

const (
	CertificateRequest HandshakePacketId = iota
	CertificateResponse

	ServerVerification
	ClientInformation
)

func SendHandshakePacket(conn net.Conn, id HandshakePacketId, payload []byte) error {
	packet := HandshakePacket{byte(id), payload}
	s := packet.Size()
	return netutils.SendToConn(conn, s, func(n int, b []byte) { packet.marshal(n, b, 0) })
}

func SendCertResponseHandshakePacket(conn net.Conn, id HandshakePacketId, cert cert.Certificate) error {
	cert.PrivateKey = nil // scary!

	b := make([]byte, cert.Size())
	cert.Marshal(b)

	packet := HandshakePacket{byte(id), b}
	s := packet.Size()
	return netutils.SendToConn(conn, s, func(n int, b []byte) { packet.marshal(n, b, 0) })
}

func UnmarshalHandshakePacket(buf []byte) (packet HandshakePacket, err error) {
	err = packet.Unmarshal(buf)
	return
}
