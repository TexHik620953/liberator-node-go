package mesh

import "net"

type EventType = int32

const (
	EventType_NewBiStreamConnection EventType = 1
)

type ConnectionEvent struct {
	Connection  *MeshConnection
	Type        EventType
	NewBiStream net.Conn
}
