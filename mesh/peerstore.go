package mesh

import (
	"liberator-node-go/infra/ipapi"
	"sync"
	"time"
)

type PeerInfo struct {
	Id        string
	Connected bool
	LastSeen  time.Time

	IpInfo *ipapi.IpInfo

	Peer *MeshConnection

	// From->rtt
	RTTMap   map[string]int64
	Adresses map[string]struct{}
}

type PeerStore struct {
	store map[string]*PeerInfo
	mut   sync.RWMutex
}

func newPeerStore() *PeerStore {
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
