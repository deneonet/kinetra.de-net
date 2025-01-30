package handshake

import (
	"net"

	"github.com/deneonet/knet/cert"
	"github.com/deneonet/knet/netutils"
)

// SendHandshakePacket sends a handshake packet with the given type and payload.
func SendHandshakePacket(conn net.Conn, typ PacketType, payload []byte, netUtilsSettings *netutils.NetUtilsSettings) error {
	packet := Packet{payload, typ}
	s := packet.Size()
	return netutils.SendToConn(conn, s, func(n int, b []byte) {
		packet.NestedMarshal(n, b, 0)
	}, netUtilsSettings)
}

// SendCertResponseHandshakePacket sends a certificate response handshake packet
// to the connection, ensuring that the certificate's private key is cleared before transmission.
func SendCertResponseHandshakePacket(conn net.Conn, cert cert.ServerCertificate, netUtilsSettings *netutils.NetUtilsSettings) error {
	cert.PrivateKey = nil // scary!
	b := make([]byte, cert.Size())
	cert.Marshal(b)
	return SendHandshakePacket(conn, PacketTypeCertificateResponse, b, netUtilsSettings)
}

// UnmarshalHandshakePacket unmarshals the given buffer into a Handshake packet.
func UnmarshalHandshakePacket(buf []byte) (packet Packet, err error) {
	err = packet.Unmarshal(buf)
	if err != nil {
		return packet, err
	}
	return packet, nil
}
