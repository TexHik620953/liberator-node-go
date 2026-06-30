package mesh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"liberator-node-go/mesh/meshproto"
	"net"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

type MeshConnection struct {
	conn      *quic.Conn
	eventSink chan<- *ConnectionEvent

	isRunning uint32

	nodeId string

	defaultClient *grpc.ClientConn
	meshService   meshproto.MeshServiceClient

	closed atomic.Bool
}

func newConnection(conn *quic.Conn, eventSink chan<- *ConnectionEvent) (*MeshConnection, error) {
	state := conn.ConnectionState().TLS
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("peer is not authenticated")
	}
	peerCert := state.PeerCertificates[0]

	if len(peerCert.Subject.CommonName) == 0 {
		return nil, fmt.Errorf("peer has no common name")
	}
	hash := sha256.Sum256(peerCert.RawSubjectPublicKeyInfo)
	nodeId := hex.EncodeToString(hash[:])

	c := &MeshConnection{
		nodeId:    nodeId,
		conn:      conn,
		eventSink: eventSink,
		closed:    atomic.Bool{},
	}
	c.closed.Store(false)
	var err error
	c.defaultClient, err = c.NewGrpcClient()
	if err != nil {
		return nil, err
	}
	c.meshService = meshproto.NewMeshServiceClient(c.defaultClient)

	return c, nil
}

func (c *MeshConnection) ID() string {
	return c.nodeId
}
func (c *MeshConnection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *MeshConnection) Close() {
	_ = c.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "closed")
}

func (c *MeshConnection) Run() {
	if !atomic.CompareAndSwapUint32(&c.isRunning, 0, 1) {
		return
	}

	ctx, cancel := context.WithCancel(c.conn.Context())
	defer cancel()

	go c.readDatagrams(ctx)
	c.acceptBiStreams(ctx)
	c.closed.Store(true)
}

func (c *MeshConnection) readDatagrams(ctx context.Context) {
	for {
		data, err := c.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		_ = data
	}
}

func (c *MeshConnection) acceptBiStreams(ctx context.Context) {
	for {
		stream, err := c.conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		c.eventSink <- &ConnectionEvent{
			Type:        EventType_NewBiStreamConnection,
			Connection:  c,
			NewBiStream: newBiStreamConn(stream, c.conn.LocalAddr(), c.conn.RemoteAddr()),
		}
	}
}

func (c *MeshConnection) NewGrpcClient() (*grpc.ClientConn, error) {
	// Настраиваем кастомный диалер для gRPC
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		stream, err := c.conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		// Заворачиваем quic.Stream в net.Conn (структура streamConn из прошлого ответа)
		return newBiStreamConn(stream, c.conn.LocalAddr(), c.conn.RemoteAddr()), nil
	}

	// Устанавливаем виртуальное gRPC соединение
	grpcConn, err := grpc.NewClient(
		"passthrough:///mesh-peer",                               // Виртуальный адрес (gRPC требует непустую строку)
		grpc.WithTransportCredentials(insecure.NewCredentials()), // TLS уже проверен на уровне QUIC
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		return nil, err
	}

	return grpcConn, nil
}

func (c *MeshConnection) ListKnownPeers(ctx context.Context) (*meshproto.ListKnownPeersResponse, error) {
	return c.meshService.ListKnownPeers(ctx, &emptypb.Empty{})
}
