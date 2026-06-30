package mesh

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"liberator-node-go/mesh/meshproto"
	"log"
	"maps"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

//conn.ConnectionStats().RTT

type MeshNode struct {
	meshproto.MeshServiceServer
	ctx context.Context
	cfg *MeshConfig

	cert         *tls.Certificate
	serverCaPool *x509.CertPool

	// This server listener
	udpBind   *net.UDPConn
	transport *quic.Transport
	lis       *quic.Listener
	nodeId    string

	connectedNodes    map[string]*MeshConnection
	connectedNodesMut sync.RWMutex

	eventSink chan *ConnectionEvent

	grpcServer        *grpc.Server
	globalBiStreamLis *BiStreamLis
}

func New(ctx context.Context, cfg *MeshConfig, cert *tls.Certificate, rootCa *x509.Certificate) (*MeshNode, error) {
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("tls certificate contains no raw chain data")
	}

	var leafCert *x509.Certificate
	var err error

	// 2. Если встроенный Leaf отсутствует, парсим его из сырых байт первого элемента
	if cert.Leaf != nil {
		leafCert = cert.Leaf
	} else {
		leafCert, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse raw tls certificate: %w", err)
		}
	}
	hash := sha256.Sum256(leafCert.RawSubjectPublicKeyInfo)
	nodeId := hex.EncodeToString(hash[:])

	n := &MeshNode{
		ctx:            ctx,
		cfg:            cfg,
		connectedNodes: make(map[string]*MeshConnection),
		cert:           cert,
		serverCaPool:   x509.NewCertPool(),
		eventSink:      make(chan *ConnectionEvent, 10),
		grpcServer:     grpc.NewServer(),
		nodeId:         nodeId,
	}
	n.serverCaPool.AddCert(rootCa)

	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}

	// Создаем один общий UDP сокет для этой ноды
	n.udpBind, err = net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	// Оборачиваем его в единый QUIC Транспорт
	n.transport = &quic.Transport{
		Conn: n.udpBind,
	}

	n.lis, err = n.transport.Listen(&tls.Config{
		Certificates: []tls.Certificate{*n.cert},
		NextProtos:   []string{"mesh"},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("target peer does not sent cert")
			}

			leafCert := cs.PeerCertificates[0]

			// Вручную запускаем валидацию цепочки по нашему CA пуллу.
			// Это защищает от Man-in-the-Middle атак.
			_, err := leafCert.Verify(x509.VerifyOptions{
				Roots:       n.serverCaPool,
				CurrentTime: time.Now(),
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				return fmt.Errorf("failed to verify peer cert: %w", err)
			}
			// Узел успешно прошел проверку! Запоминаем его логическое имя из сертификата
			return nil
		},
	}, &quic.Config{
		MaxIncomingUniStreams: 0,
	})
	if err != nil {
		return nil, err
	}

	n.globalBiStreamLis = newBiStreamLis(ctx, n.lis.Addr())

	log.Printf("created node with id: %s", n.nodeId)

	meshproto.RegisterMeshServiceServer(n.grpcServer, n)

	return n, nil
}
func (n *MeshNode) DialAddr(addr string) (*MeshConnection, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*n.cert},
		NextProtos:   []string{"mesh"},

		// 1. Отключаем дефолтную проверку по ServerName (так как мы его не знаем)
		InsecureSkipVerify: true,
		// 2. Пишем кастомную валидацию соединения
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("target peer does not sent cert")
			}

			leafCert := cs.PeerCertificates[0]

			// Вручную запускаем валидацию цепочки по нашему CA пуллу.
			// Это защищает от Man-in-the-Middle атак.
			_, err := leafCert.Verify(x509.VerifyOptions{
				Roots:       n.serverCaPool,
				CurrentTime: time.Now(),
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				return fmt.Errorf("failed to verify peer cert: %w", err)
			}
			// Узел успешно прошел проверку! Запоминаем его логическое имя из сертификата
			return nil
		},
	}

	conn, err := n.transport.Dial(n.ctx, udpAddr, tlsCfg, &quic.Config{
		MaxIncomingUniStreams: 0,
	})
	if err != nil {
		return nil, err
	}

	return n.handleConnection(conn, false)
}
func (n *MeshNode) handleConnection(conn *quic.Conn, isIncoming bool) (*MeshConnection, error) {
	meshConn, err := newConnection(conn, n.eventSink)
	if err != nil {
		return nil, err
	}

	n.connectedNodesMut.Lock()
	defer n.connectedNodesMut.Unlock()

	// Remove all closed
	toRemove := make([]string, 0)
	for k, p := range n.connectedNodes {
		if p.closed.Load() {
			toRemove = append(toRemove, k)
		}
	}
	for _, k := range toRemove {
		delete(n.connectedNodes, k)
	}

	original, ex := n.connectedNodes[meshConn.ID()]
	if ex {
		localID := n.nodeId
		remoteID := meshConn.ID()

		if localID < remoteID {
			if isIncoming {
				meshConn.Close()
				return original, nil
			}
			original.Close()
			log.Printf("Dial won collision against %s. Replacing.", meshConn.ID())
		} else {
			if !isIncoming {
				meshConn.Close()
				return original, nil
			}
			original.Close()

			log.Printf("Incoming Accept won collision against %s. Replacing.", meshConn.ID())
		}
	}

	n.connectedNodes[meshConn.ID()] = meshConn
	go meshConn.Run()

	log.Printf("established connection from %s to %s", n.nodeId, meshConn.ID())

	return meshConn, nil
}
func (n *MeshNode) handleEvent(event *ConnectionEvent) {
	switch event.Type {
	case EventType_NewBiStreamConnection:
		n.globalBiStreamLis.PushConnection(event.NewBiStream)
	}
}
func (n *MeshNode) Run() {
	// Grpc listener
	go func() {
		n.grpcServer.Serve(n.globalBiStreamLis)
	}()

	// Event sink processor
	go func() {
		for event := range n.eventSink {
			n.handleEvent(event)
		}
	}()

	go n.nodeWorker()

	// Accept connections
	for {
		select {
		case <-n.ctx.Done():
			n.lis.Close()
			n.globalBiStreamLis.Close()
			close(n.eventSink)
			return
		default:
		}
		conn, err := n.lis.Accept(n.ctx)

		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("failed to accept connection: %v", err)
			continue
		}
		go func() {
			meshConn, err := n.handleConnection(conn, true)
			if err != nil {
				meshConn.Close()
			}
		}()
	}
}

func (n *MeshNode) Addr() net.Addr {
	return n.lis.Addr()
}

func (n *MeshNode) nodeWorker() {
	// Connect to all bootstrap nodes
	for _, bn := range n.cfg.BootstrapNodes {
		_, err := n.DialAddr(bn)
		if err != nil {
			log.Printf("failed to connect to bootstrap node %s: %v", bn, err)
		}
	}

	// Some time to bootstrap and connect to everyone
	<-time.After(time.Second * 5)

	pullDiscovery := time.NewTicker(time.Second * 5)
	go func() {
		for range pullDiscovery.C {
			// Snapshot current peers not to hold mutex
			peers := make(map[string]*MeshConnection)

			n.connectedNodesMut.RLock()
			maps.Copy(peers, n.connectedNodes)
			n.connectedNodesMut.RUnlock()

			connectCandidates := map[string]*meshproto.PeerInfo{}
			for _, peer := range peers {
				peerKnown, err := peer.ListKnownPeers(n.ctx)
				if err != nil {
					log.Printf("failed to list peer know peers: %v", err)
					continue
				}
				for _, cand := range peerKnown.Peers {
					if cand.Id == n.nodeId {
						continue // Do not connect to ourself
					}
					if _, ex := peers[cand.Id]; ex {
						// TODO: Handle unreachable nodes, we cant connect to.
						continue // We already connected to this host
					}
					connectCandidates[cand.Id] = cand
				}
			}
			for _, cand := range connectCandidates {
				_, err := n.DialAddr(cand.Addr)
				if err != nil {
					log.Printf("failed to connect to new peer %s: %v", cand.Addr, err)
					continue
				}
			}

		}
	}()

	select {
	case <-n.ctx.Done():
		pullDiscovery.Stop()
	}
}

// MeshService grpc implementation

func (n *MeshNode) ListKnownPeers(ctx context.Context, _ *emptypb.Empty) (*meshproto.ListKnownPeersResponse, error) {
	resp := &meshproto.ListKnownPeersResponse{
		Peers: make([]*meshproto.PeerInfo, 0),
	}
	n.connectedNodesMut.RLock()
	for _, peer := range n.connectedNodes {
		if peer.closed.Load() {
			continue
		}
		resp.Peers = append(resp.Peers, &meshproto.PeerInfo{
			Id:   peer.ID(),
			Addr: peer.RemoteAddr().String(),
		})
	}
	n.connectedNodesMut.RUnlock()
	return resp, nil
}
