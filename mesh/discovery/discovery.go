package discovery

import (
	"context"
	"liberator-node-go/infra/ipapi"
	"liberator-node-go/mesh/meshproto"
	"maps"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"
)

type DiscoveryService struct {
	meshproto.DiscoveryServiceServer

	peerStore *PeerStore
}

func New() *DiscoveryService {
	return &DiscoveryService{
		peerStore: NewPeerStore(),
	}
}

func (svc *DiscoveryService) Store() *PeerStore {
	return svc.peerStore
}

func (svc *DiscoveryService) HandleListKnownPeers(rq *meshproto.ListKnownPeersResponse) {
	for _, peer := range rq.Peers {
		var ipInfo *ipapi.IpInfo
		if peer.IpInfo != nil {
			ipInfo = &ipapi.IpInfo{
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
				Query:       peer.IpInfo.Query,
			}
		}
		svc.peerStore.InsertMerge(&PeerInfo{
			Id:       peer.Id,
			LastSeen: time.Unix(peer.LastSeen, 0),
			IpInfo:   ipInfo,
			Addr:     peer.Addr,
		})
	}
}

// MeshService grpc implementation
func (svc *DiscoveryService) ListKnownPeers(ctx context.Context, _ *emptypb.Empty) (*meshproto.ListKnownPeersResponse, error) {
	resp := &meshproto.ListKnownPeersResponse{
		Peers: make([]*meshproto.PeerInfo, 0),
	}
	for _, peer := range svc.peerStore.List() {
		var ipInfo *meshproto.IpInfo
		if peer.IpInfo != nil {
			ipInfo = &meshproto.IpInfo{
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
		pi := &meshproto.PeerInfo{
			Id:       peer.Id,
			LastSeen: peer.LastSeen.Unix(),
			IpInfo:   ipInfo,
			Addr:     maps.Clone(peer.Addr),
		}
		resp.Peers = append(resp.Peers, pi)
	}
	return resp, nil
}
