package hub

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"github.com/parthyadav3105/wgadm/pkg/wireguard"
)

const (
	holdIP = 90 * 24 * time.Hour

	kindNode Kind = "node"
	kindApp  Kind = "app"
)

var hostRange = map[Kind][2]int{
	kindNode: {10, 199},
	kindApp:  {200, 254},
}

var validName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

type peer struct {
	Name      string     `json:"name"`
	Kind      Kind       `json:"kind"`
	IP        netip.Addr `json:"ip"`
	PublicKey string     `json:"publicKey"`
}

type hold struct {
	IP    netip.Addr `json:"ip"`
	Until time.Time  `json:"until"`
}

func (localHub) AddAppDevice(ctx context.Context, name, publicKey string) (PeerStatus, wireguard.Config, error) {
	var added peer
	var deviceConfig wireguard.Config
	err := changeStateAndApply(ctx, func(s *state) error {
		var err error
		if added, err = s.addPeer(peer{Name: name, Kind: kindApp, PublicKey: publicKey}); err != nil {
			return err
		}
		deviceConfig = wireguard.Config{
			Role:    string(kindApp),
			Address: netip.PrefixFrom(added.IP, 32),
			Peers: []wireguard.Peer{{
				Name:      "hub",
				PublicKey: s.PublicKey,
				Endpoint:  s.endpointWithPort(),
				AllowedIP: s.Subnet,
				Keepalive: 25,
			}},
		}
		return nil
	})
	return peerStatus(added, nil), deviceConfig, err
}

func (localHub) RemovePeer(ctx context.Context, name string) (PeerStatus, error) {
	var removed peer
	err := changeStateAndApply(ctx, func(s *state) error {
		var err error
		removed, err = s.removePeer(name)
		return err
	})
	return peerStatus(removed, nil), err
}

func peerStatus(p peer, handshakes map[string]time.Time) PeerStatus {
	return PeerStatus{Name: p.Name, Kind: p.Kind, IP: p.IP, PublicKey: p.PublicKey, LastHandshake: handshakes[p.PublicKey]}
}

func (s *state) findPeer(name string) (peer, bool) {
	i := slices.IndexFunc(s.Peers, func(p peer) bool { return p.Name == name })
	if i < 0 {
		return peer{}, false
	}
	return s.Peers[i], true
}

func (s *state) addPeer(p peer) (peer, error) {
	if !validName.MatchString(p.Name) {
		return peer{}, fmt.Errorf("invalid name %q: use 1-32 lowercase letters, digits and '-'", p.Name)
	}
	if !ValidPublicKey(p.PublicKey) {
		return peer{}, fmt.Errorf("invalid WireGuard public key %q", p.PublicKey)
	}
	if _, ok := s.findPeer(p.Name); ok {
		return peer{}, fmt.Errorf("%w: %s", ErrNameTaken, p.Name)
	}
	if slices.ContainsFunc(s.Peers, func(q peer) bool { return q.PublicKey == p.PublicKey }) {
		return peer{}, errors.New("public key already registered")
	}

	now := time.Now().UTC()
	s.Held = slices.DeleteFunc(s.Held, func(h hold) bool { return !now.Before(h.Until) })
	ip, err := s.freeIP(p.Kind)
	if err != nil {
		return peer{}, err
	}

	p.IP = ip
	s.Peers = append(s.Peers, p)
	return p, nil
}

// removes the peer and holds its IP so it is not reused soon.
func (s *state) removePeer(name string) (peer, error) {
	p, ok := s.findPeer(name)
	if !ok {
		return peer{}, fmt.Errorf("no such peer: %s", name)
	}
	s.Peers = slices.DeleteFunc(s.Peers, func(q peer) bool { return q.Name == name })
	s.Held = append(s.Held, hold{IP: p.IP, Until: time.Now().UTC().Add(holdIP)})
	return p, nil
}

// returns the first address in kind's range that is neither used nor held.
func (s *state) freeIP(kind Kind) (netip.Addr, error) {
	used := map[netip.Addr]bool{s.hubIP(): true}
	for _, p := range s.Peers {
		used[p.IP] = true
	}
	for _, h := range s.Held {
		used[h.IP] = true
	}

	b := s.Subnet.Masked().Addr().As4()
	r := hostRange[kind]
	for i := r[0]; i <= r[1]; i++ {
		b[3] = byte(i)
		if ip := netip.AddrFrom4(b); !used[ip] {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w for %s peers in %s", ErrSubnetFull, kind, s.Subnet)
}
