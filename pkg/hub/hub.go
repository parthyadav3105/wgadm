package hub

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/parthyadav3105/wgadm/pkg/host"
	"github.com/parthyadav3105/wgadm/pkg/wireguard"
)

const sysctlFile = "/etc/sysctl.d/99-wgadm.conf"

type localHub struct{}

// the hub on this machine.
var Local Hub = localHub{}

func (localHub) Init(ctx context.Context, endpoint string, port uint16, subnet netip.Prefix) (Info, error) {
	if !ValidSubnet(subnet) {
		return Info{}, fmt.Errorf("subnet %s must be a private IPv4 /24 like 10.66.0.0/24", subnet)
	}
	if !ValidEndpoint(endpoint) {
		return Info{}, fmt.Errorf("invalid endpoint %q: use a DNS name or IPv4 address", endpoint)
	}
	s := &state{Endpoint: endpoint, Port: port, Subnet: subnet.Masked()}
	var err error
	if s.PrivateKey, s.PublicKey, err = wireguard.GenerateKey(); err != nil {
		return Info{}, err
	}
	return install(ctx, s)
}

func (localHub) Restore(ctx context.Context, backupPath string) (Info, error) {
	if _, err := os.Stat(backupPath); err != nil {
		return Info{}, err
	}
	s, err := loadState(backupPath)
	if err != nil {
		return Info{}, err
	}
	if !ValidEndpoint(s.Endpoint) || !ValidSubnet(s.Subnet) {
		return Info{}, fmt.Errorf("invalid backup: endpoint %q, subnet %s", s.Endpoint, s.Subnet)
	}
	if !ValidPublicKey(s.PrivateKey) {
		return Info{}, errors.New("invalid backup: bad hub private key")
	}
	for _, p := range s.Peers {
		if !ValidPublicKey(p.PublicKey) || !validName.MatchString(p.Name) {
			return Info{}, fmt.Errorf("invalid backup: bad peer %q", p.Name)
		}
	}
	s.JoinTokens = nil
	return install(ctx, s)
}

func (localHub) Backup(path string) error {
	s, err := loadState(statePath)
	if err != nil {
		return err
	}
	return s.save(path)
}

func (localHub) Uninstall(ctx context.Context) error {
	if err := wireguard.Down(ctx); err != nil {
		return err
	}
	if err := os.RemoveAll(sysctlFile); err != nil {
		return err
	}
	if err := removeJoinUser(ctx); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Dir(statePath)); err != nil {
		return err
	}
	return host.RemoveExecutable()
}

func (localHub) Status(ctx context.Context) (Info, error) {
	s, err := loadState(statePath)
	if err != nil {
		return Info{}, err
	}
	handshakes, err := wireguard.Handshakes(ctx)
	if err != nil {
		return Info{}, err
	}
	return s.info(handshakes), nil
}

func install(ctx context.Context, s *state) (Info, error) {
	if _, err := os.Stat(statePath); err == nil {
		return Info{}, ErrAlreadyInitialized
	}
	owner, err := wireguard.ConfigOwner()
	if err != nil {
		return Info{}, err
	}
	if owner != "" && owner != "hub" {
		return Info{}, fmt.Errorf("this machine is already a wgadm %s", owner)
	}
	if err := host.InstallMissingAptPackages(ctx, map[string]string{"wg": "wireguard-tools", "wg-quick": "wireguard-tools", "iptables": "iptables", "sudo": "sudo", "ssh-keygen": "openssh-client"}); err != nil {
		return Info{}, err
	}
	if err := enableIPForward(ctx); err != nil {
		return Info{}, err
	}
	if err := setupJoinUser(ctx, s.JoinTokens); err != nil {
		return Info{}, err
	}
	if err := wireguard.Apply(ctx, s.tunnelConfig()); err != nil {
		return Info{}, err
	}
	if err := s.save(statePath); err != nil {
		return Info{}, err
	}
	return s.info(nil), nil
}

func enableIPForward(ctx context.Context) error {
	if err := os.WriteFile(sysctlFile, []byte("net.ipv4.ip_forward = 1\n"), 0o644); err != nil {
		return err
	}
	_, err := host.Run(ctx, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
	return err
}

func (s *state) hubIP() netip.Addr {
	return s.Subnet.Masked().Addr().Next()
}

func (s *state) endpointWithPort() string {
	return net.JoinHostPort(s.Endpoint, strconv.Itoa(int(s.Port)))
}

func (s *state) tunnelConfig() wireguard.Config {
	rules := func(op string) string {
		return fmt.Sprintf("iptables %[1]s INPUT -p udp --dport %[2]d -j ACCEPT; iptables %[1]s FORWARD -i %%i -o %%i -j ACCEPT; iptables %[1]s FORWARD -i %%i ! -o %%i -j DROP", op, s.Port)
	}
	cfg := wireguard.Config{
		Role:       "hub",
		PrivateKey: s.PrivateKey,
		Address:    netip.PrefixFrom(s.hubIP(), s.Subnet.Bits()),
		ListenPort: s.Port,
		PostUp:     rules("-I"),
		PostDown:   rules("-D"),
	}
	for _, p := range s.Peers {
		cfg.Peers = append(cfg.Peers, wireguard.Peer{Name: p.Name, PublicKey: p.PublicKey, AllowedIP: netip.PrefixFrom(p.IP, 32)})
	}
	return cfg
}

func (s *state) info(handshakes map[string]time.Time) Info {
	info := Info{
		Endpoint: s.Endpoint,
		Port:     s.Port,
		Subnet:   s.Subnet,
		Address:  netip.PrefixFrom(s.hubIP(), s.Subnet.Bits()),
		Up:       wireguard.IsUp(),
		Peers:    make([]PeerStatus, len(s.Peers)),
	}
	for i, p := range s.Peers {
		info.Peers[i] = peerStatus(p, handshakes)
	}
	return info
}

// drops expired join tokens, runs change, then applies the result to the tunnel.
func changeStateAndApply(ctx context.Context, change func(s *state) error) error {
	return changeStateUnderLock(func(s *state) error {
		s.JoinTokens = slices.DeleteFunc(s.JoinTokens, func(t joinToken) bool { return !time.Now().Before(t.Expires) })
		if err := change(s); err != nil {
			return err
		}
		return wireguard.Apply(ctx, s.tunnelConfig())
	})
}
