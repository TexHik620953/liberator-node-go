package mesh

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"liberator-node-go/infra/ipapi"
	"liberator-node-go/mesh/components"
	"liberator-node-go/mesh/connection"
	"liberator-node-go/mesh/meshproto"
	"log"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type MeshConfig struct {
	ListenAddr     string
	BootstrapNodes []string
}

type MeshNode struct {
	ctx    context.Context
	cfg    *MeshConfig
	ipInfo *ipapi.IpInfo

	cert         *tls.Certificate
	serverCaPool *x509.CertPool

	// This server listener
	udpBind   *net.UDPConn
	transport *quic.Transport
	lis       *quic.Listener
	nodeId    string

	eventSink chan *connection.ConnectionEvent

	grpcServer        *grpc.Server
	globalBiStreamLis *connection.BiStreamLis

	discovery *DiscoveryService
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
		ctx:          ctx,
		cfg:          cfg,
		cert:         cert,
		serverCaPool: x509.NewCertPool(),
		eventSink:    make(chan *connection.ConnectionEvent, 10),
		grpcServer:   grpc.NewServer(),
		nodeId:       nodeId,
	}
	n.serverCaPool.AddCert(rootCa)

	/*
		n.ipInfo, err = ipapi.GetIpInfo()
		if err != nil {
			return nil, err
		}*/
	{
		// Add self to peerstore
		pi, ex := n.peerStore.Get(n.nodeId)
		if !ex {
			pi = &components.PeerInfo{
				Id:        n.nodeId,
				Connected: false,
				IpInfo:    nil,
				LastSeen:  time.Now(),
				RTTMap:    map[string]int64{},
				Adresses:  map[string]struct{}{},
			}
			n.peerStore.Set(pi)
		}
		pi.IpInfo = n.ipInfo
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}

	n.udpBind, err = net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
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

	n.globalBiStreamLis = connection.NewBiStreamLis(ctx, n.lis.Addr())

	log.Printf("created node with id: %s", n.nodeId)

	meshproto.RegisterMeshServiceServer(n.grpcServer, n)

	return n, nil
}
func (n *MeshNode) meshConnect(addr string) (*connection.MeshConnection, error) {
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
func (n *MeshNode) handleConnection(conn *quic.Conn, isIncoming bool) (*connection.MeshConnection, error) {
	meshConn, err := connection.NewMeshConnection(conn, n.eventSink, func(mc *connection.MeshConnection) {
		conn, ex := n.peerStore.Get(mc.ID())
		if ex {
			conn.Connected = false
		}
	})
	if err != nil {
		return nil, err
	}
	if meshConn.ID() == n.nodeId {
		return nil, fmt.Errorf("cant connect to itself")
	}

	original, ex := n.peerStore.GetConnected(meshConn.ID())
	if ex {
		localID := n.nodeId
		remoteID := meshConn.ID()

		if localID < remoteID {
			if isIncoming {
				meshConn.Close()
				return original.Peer, nil
			}
			original.Peer.Close()
			log.Printf("Dial won collision against %s. Replacing.", meshConn.ID())
		} else {
			if !isIncoming {
				meshConn.Close()
				return original.Peer, nil
			}
			original.Peer.Close()

			log.Printf("Incoming Accept won collision against %s. Replacing.", meshConn.ID())
		}
	}

	n.peerStore.Set(&components.PeerInfo{
		Id:        meshConn.ID(),
		Peer:      meshConn,
		Connected: true,
		IpInfo:    nil,
		LastSeen:  time.Now(),
		RTTMap:    map[string]int64{},
		Adresses:  map[string]struct{}{},
	})
	go meshConn.Run()

	return meshConn, nil
}
func (n *MeshNode) handleEvent(event *connection.ConnectionEvent) {
	switch event.Type {
	case connection.EventType_NewBiStreamConnection:
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
			if err != nil && meshConn != nil {
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
		_, err := n.meshConnect(bn)
		if err != nil {
			log.Printf("failed to connect to bootstrap node %s: %v", bn, err)
		}
	}

	pullDiscovery := time.NewTicker(time.Second * 2)
	rttUpdate := time.NewTicker(time.Second * 2)
	connector := time.NewTicker(time.Second * 2)
	go func() {
		for range pullDiscovery.C {
			select {
			case <-n.ctx.Done():
				return
			default:
			}

			// Collect peers info from all connected peers
			peerInfos := map[string][]*meshproto.PeerInfo{}
			for _, peer := range n.peerStore.ListConnected() {
				peerKnown, err := peer.Peer.ListKnownPeers(n.ctx)
				if err != nil {
					log.Printf("failed to list peer know peers: %v", err)
					continue
				}
				peerInfos[peer.Id] = peerKnown.Peers
			}

			for _, knownPeers := range peerInfos {
				for _, cand := range knownPeers {
					var ipInfo *ipapi.IpInfo
					if cand.IpInfo != nil {
						ipInfo = &ipapi.IpInfo{
							Country:     cand.IpInfo.Country,
							CountryCode: cand.IpInfo.CountryCode,
							Region:      cand.IpInfo.Region,
							RegionName:  cand.IpInfo.RegionName,
							City:        cand.IpInfo.City,
							Zip:         cand.IpInfo.Zip,
							Lat:         cand.IpInfo.Lat,
							Lon:         cand.IpInfo.Lon,
							Timezone:    cand.IpInfo.Timezone,
							Isp:         cand.IpInfo.Isp,
							Org:         cand.IpInfo.Org,
							As:          cand.IpInfo.As,
							Query:       cand.IpInfo.Query,
						}
					}
					if !n.peerStore.Exists(cand.Id) {
						// Add basic peer info if its new for us
						pi := &PeerInfo{
							Id:        cand.Id,
							Connected: false,
							LastSeen:  time.Unix(cand.LastSeen, 0),
							RTTMap:    map[string]int64{},
							Adresses:  map[string]struct{}{},
						}
						// parse all adresses
						if _, err := net.ResolveUDPAddr("udp", cand.Addr); err == nil && len(cand.Addr) > 0 {
							pi.Adresses[cand.Addr] = struct{}{}
						}
						if cand.IpInfo != nil {
							pi.IpInfo = ipInfo
							if _, err := net.ResolveUDPAddr("udp", ipInfo.Query); err == nil && len(ipInfo.Query) > 0 {
								pi.Adresses[ipInfo.Query] = struct{}{}
							}
						}
						n.peerStore.Set(pi)
					} else {
						// Update its info, if we already know about this peer
						pi, ex := n.peerStore.Get(cand.Id)
						if !ex {
							continue
						}
						pi.IpInfo = ipInfo
					}
				}
			}
			// Now when all peers added, update rttmap
			for infoOrigin, knownPeers := range peerInfos {
				for _, peerInfo := range knownPeers {
					peer, ex := n.peerStore.Get(peerInfo.Id)
					if !ex {
						continue // Should not happen
					}
					peer.RTTMap[infoOrigin] = peerInfo.Rtt
				}
			}
		}
	}()

	go func() {
		for range rttUpdate.C {
			select {
			case <-n.ctx.Done():
				return
			default:
			}
			/*
				for _, peer := range n.peerStore.ListConnected() {
					rtt := peer.Peer.conn.ConnectionStats().SmoothedRTT.Microseconds()
				}
			*/
		}
	}()

	go func() {
		for range connector.C {
			select {
			case <-n.ctx.Done():
				return
			default:
			}
			// Do not connect to outselfs
			for _, connCand := range n.peerStore.ListUnconnected() {
				if connCand.Id == n.nodeId {
					continue
				}

				go func(cand *PeerInfo) {
					for addr, _ := range cand.Adresses {
						peer, err := n.meshConnect(addr)
						if err != nil {
							log.Printf("failed to connect to new peer %s: %v", addr, err)
							continue
						}

						pi, ex := n.peerStore.Get(peer.ID())
						if !ex {
							pi = &PeerInfo{
								Id:        peer.ID(),
								Connected: true,
								Peer:      peer,
								LastSeen:  time.Now(),
								RTTMap:    map[string]int64{},
								Adresses:  map[string]struct{}{},
							}
							n.peerStore.Set(pi)
						}
						if peer.ID() != cand.Id {
							// Collision, node behind this addr has different id
							// Remove addr from node ips, and assign to new connection
							delete(cand.Adresses, addr)
							pi.Adresses[addr] = struct{}{}
							return
						} else {
							pi.Connected = true
							pi.LastSeen = time.Now()
							pi.Peer = peer
						}
						return
					}
				}(connCand)
			}
		}
	}()

	select {
	case <-n.ctx.Done():
		pullDiscovery.Stop()
		rttUpdate.Stop()
	}
}
func (n *MeshNode) PeerStore() *components.PeerStore {
	return n.peerStore
}

// MeshService grpc implementation
func (n *MeshNode) ListKnownPeers(ctx context.Context, _ *emptypb.Empty) (*meshproto.ListKnownPeersResponse, error) {
	resp := &meshproto.ListKnownPeersResponse{
		Peers: make([]*meshproto.PeerInfo, 0),
	}

	for _, peer := range n.peerStore.List() {
		pi := &meshproto.PeerInfo{
			Id:       peer.Id,
			LastSeen: peer.LastSeen.Unix(),
		}
		if peer.Connected {
			pi.Addr = peer.Peer.RemoteAddr().String()
		}
		rtt, ex := peer.RTTMap[n.nodeId]
		if ex {
			pi.Rtt = rtt
		}

		if peer.IpInfo != nil {
			pi.IpInfo = &meshproto.IpInfo{
				Country:     peer.IpInfo.Country,
				CountryCode: peer.IpInfo.CountryCode,
				Region:      peer.IpInfo.Region,
				RegionName:  peer.IpInfo.RegionName,
				City:        peer.IpInfo.City,
				Zip:         peer.IpInfo.Zip,
				Lat:         peer.IpInfo.Lat,
				Lon:         peer.IpInfo.Lon,
				Timezone:    peer.IpInfo.Timezone,
				Isp:         peer.IpInfo.Isp,
				Org:         peer.IpInfo.Org,
				As:          peer.IpInfo.As,
				Query:       peer.IpInfo.As,
			}
		}
		resp.Peers = append(resp.Peers, pi)
	}
	return resp, nil
}
