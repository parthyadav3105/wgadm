package hub

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"regexp"
	"time"

	"github.com/parthyadav3105/wgadm/pkg/wireguard"
)

// the restricted SSH user that join tokens log in as.
const JoinUser = "wgadm-join"

var (
	ErrNotInitialized     = errors.New("this machine is not a hub")
	ErrAlreadyInitialized = errors.New("this machine is already a hub")
	ErrNameTaken          = errors.New("name already in use")
	ErrSubnetFull         = errors.New("no free address left")
)

var validEndpoint = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$`)

func ValidEndpoint(host string) bool {
	return validEndpoint.MatchString(host)
}

func ValidSubnet(subnet netip.Prefix) bool {
	return subnet.Addr().Is4() && subnet.Bits() == 24 && subnet.Addr().IsPrivate()
}

func ValidPublicKey(k string) bool {
	// the length check matters, the decoder skips newlines that would break the config.
	b, err := base64.StdEncoding.DecodeString(k)
	return err == nil && len(b) == 32 && len(k) == 44
}

type Hub interface {
	// makes this machine the hub.
	Init(ctx context.Context, endpoint string, port uint16, subnet netip.Prefix) (Info, error)

	// rebuilds the hub on this machine from a backup file.
	Restore(ctx context.Context, backupPath string) (Info, error)

	// writes the hub's keys and peers to a file.
	Backup(path string) error

	// removes the hub and everything wgadm added to this machine, including its binary.
	Uninstall(ctx context.Context) error

	// reports the hub's settings, whether its tunnel is up, and its peers.
	Status(ctx context.Context) (Info, error)

	// creates a token that can join one node, valid for validFor.
	CreateJoinToken(ctx context.Context, validFor time.Duration) (JoinToken, error)

	// registers a node and consumes the token it logged in with.
	JoinNode(ctx context.Context, tokenID string, req JoinRequest) (JoinReply, error)

	// registers an app device, the returned config has no private key, the caller fills it in.
	AddAppDevice(ctx context.Context, name, publicKey string) (PeerStatus, wireguard.Config, error)

	// revokes a peer immediately.
	RemovePeer(ctx context.Context, name string) (PeerStatus, error)
}

// node for a joined Linux machine, app for a device using the WireGuard app.
type Kind string

type Info struct {
	Endpoint string       `json:"endpoint"`
	Port     uint16       `json:"port"`
	Subnet   netip.Prefix `json:"subnet"`
	Address  netip.Prefix `json:"address"`
	Up       bool         `json:"up"`
	Peers    []PeerStatus `json:"peers"`
}

type PeerStatus struct {
	Name          string     `json:"name"`
	Kind          Kind       `json:"kind"`
	IP            netip.Addr `json:"ip"`
	PublicKey     string     `json:"publicKey"`
	LastHandshake time.Time  `json:"lastHandshake,omitzero"`
}

// everything a machine needs to reach the hub once and join it.
type JoinToken struct {
	Host           string `json:"host"`
	SSHPort        string `json:"sshPort"`
	PrivateKey     string `json:"privateKey"`
	SSHFingerprint string `json:"sshFingerprint"`
}

// what a node sends to the hub to join.
type JoinRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

// what a node needs to start its tunnel, or why it was refused.
type JoinReply struct {
	Error        string       `json:"error,omitempty"`
	IP           netip.Addr   `json:"ip,omitzero"`
	Subnet       netip.Prefix `json:"subnet,omitzero"`
	Endpoint     string       `json:"endpoint,omitempty"`
	HubPublicKey string       `json:"hubPublicKey,omitempty"`
}
