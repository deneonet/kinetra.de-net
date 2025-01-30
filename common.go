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
	ErrSessionNotFound              = errors.New("no session associated with that connection found")
	ErrInvalidRootKey               = errors.New("invalid root key in client struct")
	ErrInvalidHandshakePacket       = errors.New("invalid handshake packet received")
	ErrDecryptingServerVerification = errors.New("error decrypting server verification")
	ErrDataExceededBufferSize       = errors.New("received data size exceeded buffer size")
)
