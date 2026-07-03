package ingress

import (
	"context"
	"crypto/tls"
	"liberator-node-go/ingress/ingressproto"
	"liberator-node-go/utils/liberatorjwt"
	"liberator-node-go/utils/safemap"
	"log"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type Ingress struct {
	ctx  context.Context
	cert *tls.Certificate

	udpBind   *net.UDPConn
	transport *quic.Transport
	lis       *quic.Listener

	jwtSecret []byte

	connections safemap.Safemap[string, *IngressConnection]
}

func New(ctx context.Context, lisAddr string, jwtSecret []byte, cert *tls.Certificate) (*Ingress, error) {
	ig := &Ingress{
		ctx:         ctx,
		cert:        cert,
		connections: safemap.New[string, *IngressConnection](),
		jwtSecret:   jwtSecret,
	}

	addr, err := net.ResolveUDPAddr("udp", lisAddr)
	if err != nil {
		return nil, err
	}

	ig.udpBind, err = net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	ig.transport = &quic.Transport{
		Conn: ig.udpBind,
	}

	ig.lis, err = ig.transport.Listen(&tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"mesh"},
		ClientAuth:   tls.NoClientCert,
	}, &quic.Config{
		MaxIncomingUniStreams: 0,
		MaxIdleTimeout:        120 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		EnableDatagrams:       true,
	})
	if err != nil {
		return nil, err
	}
	return ig, nil
}

func (ig *Ingress) Run() {
	for {
		select {
		case <-ig.ctx.Done():
			return
		default:
		}
		conn, err := ig.lis.Accept(ig.ctx)
		if err != nil {
			log.Printf("failed to accept ingress connection: %v", err)
			continue
		}
		wc, err := wrapConnetion(conn, ig, func(c *IngressConnection) {
			ig.connections.Delete(c.ConnectionID())
		})
		if err != nil {
			log.Printf("failed to wrap ingress connection: %v", err)
			continue
		}
		ig.connections.Set(wc.ConnectionID(), wc)

		go wc.Run()
	}
}

func (ig *Ingress) Authorize(ctx context.Context, source *IngressConnection, rq *ingressproto.AuthorizeRequest) (*ingressproto.AuthorizeResponse, error) {
	claims, userID, err := liberatorjwt.Verify(rq.Token, ig.jwtSecret)
	if err != nil {
		reason := err.Error()
		return &ingressproto.AuthorizeResponse{
			Ok:     false,
			Reason: &reason,
		}, nil
	}

	source.SetUserID(userID)
	_ = claims

	return &ingressproto.AuthorizeResponse{
		Ok:     true,
		Reason: nil,
	}, nil
}

func (ig *Ingress) Datagram(ctx context.Context, source *IngressConnection, data []byte) {
	if !source.IsAuthorized() {
		return
	}

}
