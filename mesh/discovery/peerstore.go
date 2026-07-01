package discovery

import (
	"liberator-node-go/infra/ipapi"
	"liberator-node-go/mesh/connection"
	"net"
	"sync"
	"time"
)

type PeerInfo struct {
	Id        string
	Connected bool
	LastSeen  time.Time
	IpInfo    *ipapi.IpInfo

	Peer *connection.MeshConnection

	Addr      map[string]bool
	addrsLock sync.Mutex
}

type PeerStore struct {
	store map[string]*PeerInfo
	mut   sync.RWMutex
}

func NewPeerStore() *PeerStore {
	return &PeerStore{
		store: make(map[string]*PeerInfo),
	}
}

func (ps *PeerStore) List() []*PeerInfo {
	ps.mut.RLock()
	defer ps.mut.RUnlock()

	r := make([]*PeerInfo, 0, len(ps.store))
	for _, v := range ps.store {
		r = append(r, v)
	}
	return r
}
func (ps *PeerStore) ListConnected() []*PeerInfo {
	ps.mut.RLock()
	defer ps.mut.RUnlock()

	r := make([]*PeerInfo, 0, len(ps.store))
	for _, v := range ps.store {
		if !v.Connected {
			continue
		}
		r = append(r, v)
	}
	return r
}
func (ps *PeerStore) ListUnconnected() []*PeerInfo {
	ps.mut.RLock()
	defer ps.mut.RUnlock()

	r := make([]*PeerInfo, 0, len(ps.store))
	for _, v := range ps.store {
		if v.Connected {
			continue
		}
		r = append(r, v)
	}
	return r
}

func (ps *PeerStore) Exists(key string) bool {
	ps.mut.RLock()
	defer ps.mut.RUnlock()

	_, ex := ps.store[key]
	return ex
}

func (ps *PeerStore) Get(key string) (*PeerInfo, bool) {
	ps.mut.RLock()
	defer ps.mut.RUnlock()

	v, ex := ps.store[key]
	if !ex {
		return nil, false
	}
	return v, true
}
func (ps *PeerStore) GetConnected(key string) (*PeerInfo, bool) {
	ps.mut.RLock()
	defer ps.mut.RUnlock()

	v, ex := ps.store[key]
	if !ex {
		return nil, false
	}
	if !v.Connected {
		return nil, false
	}
	return v, true
}

func (ps *PeerStore) Set(info *PeerInfo) {
	ps.mut.Lock()
	defer ps.mut.Unlock()

	ps.store[info.Id] = info
}

func (ps *PeerStore) InsertMerge(update *PeerInfo) {
	pi, ex := ps.Get(update.Id)
	if !ex {
		ps.Set(pi)
		return
	}

	// Merge addresses map
	pi.addrsLock.Lock()
	update.addrsLock.Lock()
	for a, _ := range update.Addr {
		if len(a) == 0 {
			continue
		}
		if _, err := net.ResolveUDPAddr("udp", a); err != nil {
			continue
		}
		pi.Addr[a] = true
	}
	update.addrsLock.Unlock()
	pi.addrsLock.Unlock()

	if update.LastSeen.After(pi.LastSeen) {
		pi.LastSeen = update.LastSeen
	}

	if update.IpInfo != nil {
		pi.IpInfo = update.IpInfo
	}
}
