package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/parthyadav3105/wgadm/pkg/host"
	"github.com/parthyadav3105/wgadm/pkg/hub"
	"github.com/parthyadav3105/wgadm/pkg/wireguard"
)

var (
	ErrAlreadyJoined = errors.New("this machine has already joined a hub")
	ErrNotJoined     = errors.New("this machine has not joined a hub")
)

// registers this machine with the hub once and starts its tunnel.
func Join(ctx context.Context, token hub.JoinToken, name string) (netip.Addr, error) {
	owner, err := wireguard.ConfigOwner()
	if err != nil {
		return netip.Addr{}, err
	}
	if owner == "node" {
		return netip.Addr{}, ErrAlreadyJoined
	}
	if owner != "" {
		return netip.Addr{}, fmt.Errorf("this machine is already a wgadm %s", owner)
	}

	if err := host.InstallMissingAptPackages(ctx, map[string]string{"wg": "wireguard-tools", "wg-quick": "wireguard-tools", "ssh": "openssh-client", "ssh-keyscan": "openssh-client", "ssh-keygen": "openssh-client"}); err != nil {
		return netip.Addr{}, err
	}
	privateKey, publicKey, err := wireguard.GenerateKey()
	if err != nil {
		return netip.Addr{}, err
	}

	reply, err := sendJoinRequestToHub(ctx, token, hub.JoinRequest{Name: name, PublicKey: publicKey})
	if err != nil {
		return netip.Addr{}, err
	}
	if err := validateHubReply(reply); err != nil {
		return netip.Addr{}, err
	}

	err = wireguard.Apply(ctx, wireguard.Config{
		Role:       "node",
		PrivateKey: privateKey,
		Address:    netip.PrefixFrom(reply.IP, 32),
		Peers: []wireguard.Peer{{
			Name:      "hub",
			PublicKey: reply.HubPublicKey,
			Endpoint:  reply.Endpoint,
			AllowedIP: reply.Subnet,
			Keepalive: 25,
		}},
	})
	return reply.IP, err
}

func requireJoined() error {
	owner, err := wireguard.ConfigOwner()
	if err != nil {
		return err
	}
	if owner != "node" {
		return ErrNotJoined
	}
	return nil
}

// removes the tunnel if joined, then deletes the wgadm binary, the hub keeps the peer until it is removed there.
func Uninstall(ctx context.Context) error {
	err := requireJoined()
	if err != nil && !errors.Is(err, ErrNotJoined) {
		return err
	}
	if err == nil {
		if err := wireguard.Down(ctx); err != nil {
			return err
		}
	}
	return host.RemoveExecutable()
}

type Info struct {
	IP            netip.Addr `json:"ip"`
	Hub           string     `json:"hub"`
	Up            bool       `json:"up"`
	LastHandshake time.Time  `json:"lastHandshake,omitzero"`
}

func Status(ctx context.Context) (Info, error) {
	if err := requireJoined(); err != nil {
		return Info{}, err
	}
	address, endpoint, err := wireguard.ConfigAddressAndEndpoint()
	if err != nil {
		return Info{}, err
	}
	handshakes, err := wireguard.Handshakes(ctx)
	if err != nil {
		return Info{}, err
	}
	info := Info{IP: address.Addr(), Hub: endpoint, Up: wireguard.IsUp()}
	for _, t := range handshakes {
		info.LastHandshake = t
	}
	return info, nil
}

// rejects values that could inject config lines into this machine's tunnel.
func validateHubReply(reply hub.JoinReply) error {
	if !hub.ValidSubnet(reply.Subnet) || !reply.Subnet.Contains(reply.IP) {
		return fmt.Errorf("hub sent an invalid address %s in subnet %s", reply.IP, reply.Subnet)
	}
	if !hub.ValidPublicKey(reply.HubPublicKey) {
		return fmt.Errorf("hub sent an invalid WireGuard public key %q", reply.HubPublicKey)
	}

	endpointHost, endpointPort, splitErr := net.SplitHostPort(reply.Endpoint)
	_, portErr := strconv.ParseUint(endpointPort, 10, 16)
	if splitErr != nil || portErr != nil || !hub.ValidEndpoint(endpointHost) {
		return fmt.Errorf("hub sent an invalid endpoint %q", reply.Endpoint)
	}
	return nil
}
