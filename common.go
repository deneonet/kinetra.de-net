package knet

import "errors"

type ReadInfo struct {
	Err  error
	Data []byte
}

type Packet interface {
	Marshal([]byte)
	Size() int
}

type AfterAction int

const (
	// None indicates that no action should occur following an event.
	None AfterAction = iota

	// Close closes the connection.
	Close
)

var (
	ErrSessionNotFound          = errors.New("no session with that remote address found")
	ErrDecryptingVerificationId = errors.New("error decrypting verification id")
	ErrInvalidHandshakePacket   = errors.New("invalid handshake packet received")
	ErrBufTooSmall              = errors.New("buffer is too small for the requested size")
	ErrInvalidRootKey           = errors.New("invalid root key in client struct")
	ErrDataExceededBufferSize   = errors.New("received data size exceeded buffer size")
)
