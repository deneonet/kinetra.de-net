package netutils

import (
	"io"
	"net"
	"time"

	"github.com/deneonet/benc"
	bstd "github.com/deneonet/benc/std"
)

type NetUtilsSettings struct {
	HandshakeReadDeadline  time.Duration
	HandshakeWriteDeadline time.Duration

	ReadDeadline  time.Duration
	WriteDeadline time.Duration

	HandshakeCompleted bool
}

func readFull(r io.Reader, s int, buf []byte) (n int, err error) {
	if len(buf) < s {
		return 0, benc.ErrBufTooSmall
	}

	for n < s && err == nil {
		var nn int
		nn, err = r.Read(buf[n:s])
		n += nn
	}

	if n >= s {
		return n, nil
	}

	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func setReadDeadline(conn net.Conn, settings *NetUtilsSettings) {
	conn.SetReadDeadline(time.Time{})

	readDeadline := settings.ReadDeadline
	if !settings.HandshakeCompleted {
		readDeadline = settings.HandshakeReadDeadline
	}

	if readDeadline > 0 {
		conn.SetReadDeadline(time.Now().Add(readDeadline))
	}
}

func setWriteDeadline(conn net.Conn, settings *NetUtilsSettings) {
	conn.SetWriteDeadline(time.Time{})

	writeDeadline := settings.WriteDeadline
	if !settings.HandshakeCompleted {
		writeDeadline = settings.HandshakeWriteDeadline
	}

	if writeDeadline > 0 {
		conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	}
}

func ReadFromConn(conn net.Conn, buf []byte, settings *NetUtilsSettings) (s uint32, err error) {
	setReadDeadline(conn, settings)

	if _, err = readFull(conn, 4, buf); err != nil {
		return
	}

	_, s, err = bstd.UnmarshalUint32(0, buf)
	if err != nil {
		return
	}

	if _, err = readFull(conn, int(s), buf[4:]); err != nil {
		return
	}

	s += 4
	return
}

// Buffer pool for efficient memory management, TODO: Custom buffer size
var bufPool = benc.NewBufPool(benc.WithBufferSize(4092 * 2 * 2 * 2 * 2))

func SendToConn(conn net.Conn, s int, f func(n int, b []byte), settings *NetUtilsSettings) (err error) {
	setWriteDeadline(conn, settings)

	fs := s + bstd.SizeUint32()

	_, errT := bufPool.Marshal(fs, func(b []byte) (n int) {
		n = bstd.MarshalUint32(0, b, uint32(s))
		f(n, b)
		_, err = conn.Write(b)
		return
	})

	if err != nil {
		return
	}

	err = errT
	return
}
