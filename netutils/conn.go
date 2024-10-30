package netutils

import (
	"errors"
	"io"
	"net"

	"github.com/deneonet/benc"
	bstd "github.com/deneonet/benc/std"
)

var (
	ErrBufTooSmall = errors.New("buffer is too small for the requested size")
)

func readFull(r io.Reader, s int, buf []byte) (n int, err error) {
	if len(buf) < s {
		return 0, ErrBufTooSmall
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

func ReadFromConn(conn net.Conn, buf []byte) (s uint32, err error) {
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

// TODO: buffer size
var bufPool = benc.NewBufPool(benc.WithBufferSize(4092 * 2 * 2 * 2 * 2))

func SendToConn(conn net.Conn, s int, f func(n int, b []byte)) (err error) {
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
