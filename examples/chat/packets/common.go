package packets

const (
	InitializationUsernamePacket int = iota
	InitializationResponsePacket

	MessagePacket
	MessageResponsePacket
)

type Message struct {
	Username string
	Message  string

	HasDisconnected bool // After someone disconnected, everyone can reclaim that username, so in order to extinguish the "new user" from the "old users", a "disconnected" mark is appended to the message
}
