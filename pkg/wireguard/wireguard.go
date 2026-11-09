package wireguard

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/parthyadav3105/wgadm/pkg/host"
)

const (
	Iface    = "vpn0"
	confPath = "/etc/wireguard/" + Iface + ".conf"
	marker   = "# managed-by: wgadm"
)

func GenerateKey() (private, public string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	enc := base64.StdEncoding.EncodeToString
	return enc(k.Bytes()), enc(k.PublicKey().Bytes()), nil
}

type Config struct {
	Role       string
	PrivateKey string
	Address    netip.Prefix
	ListenPort uint16
	PostUp     string
	PostDown   string
	Peers      []Peer
}

type Peer struct {
	Name      string
	PublicKey string
	Endpoint  string
	AllowedIP netip.Prefix
	Keepalive int
}

func (c Config) Render() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s\n[Interface]\nPrivateKey = %s\nAddress = %s\n", marker, c.Role, c.PrivateKey, c.Address)
	if c.ListenPort != 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", c.ListenPort)
	}
	if c.PostUp != "" {
		fmt.Fprintf(&b, "PostUp = %s\nPostDown = %s\n", c.PostUp, c.PostDown)
	}
	for _, p := range c.Peers {
		fmt.Fprintf(&b, "\n# %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", p.Name, p.PublicKey, p.AllowedIP)
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.Keepalive != 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
		}
	}
	return b.Bytes()
}

// returns the role in the config's marker line, empty if there is no config.
func ConfigOwner() (string, error) {
	data, err := os.ReadFile(confPath)
	if err != nil {
		return "", nil
	}
	firstLine, _, _ := strings.Cut(string(data), "\n")
	owner, ok := strings.CutPrefix(firstLine, marker+" ")
	if !ok {
		return "", fmt.Errorf("%s exists and is not managed by wgadm", confPath)
	}
	return owner, nil
}

// reads this machine's tunnel address and its peer's endpoint from the config.
func ConfigAddressAndEndpoint() (address netip.Prefix, endpoint string, err error) {
	data, err := os.ReadFile(confPath)
	if err != nil {
		return netip.Prefix{}, "", err
	}
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(line, "Address = "); ok {
			if address, err = netip.ParsePrefix(value); err != nil {
				return netip.Prefix{}, "", err
			}
		}
		if value, ok := strings.CutPrefix(line, "Endpoint = "); ok {
			endpoint = value
		}
	}
	return address, endpoint, nil
}

func IsUp() bool {
	_, err := os.Stat("/sys/class/net/" + Iface)
	return err == nil
}

// writes the config, then syncs the running tunnel or starts it if down.
func Apply(ctx context.Context, c Config) error {
	up := IsUp()
	// wg syncconf picks a random port when the config has none.
	if up && c.ListenPort == 0 {
		port, err := currentListenPort(ctx)
		if err != nil {
			return err
		}
		c.ListenPort = port
	}

	if err := host.WriteFileAtomic(confPath, c.Render(), 0o600); err != nil {
		return err
	}
	if !up {
		if _, err := host.Run(ctx, "systemctl", "enable", "wg-quick@"+Iface); err != nil {
			return err
		}
		_, err := host.Run(ctx, "systemctl", "restart", "wg-quick@"+Iface)
		return err
	}
	stripped, err := host.Run(ctx, "wg-quick", "strip", Iface)
	if err != nil {
		return err
	}
	_, err = host.RunWithStdin(ctx, stripped, "wg", "syncconf", Iface, "/dev/stdin")
	return err
}

func currentListenPort(ctx context.Context) (uint16, error) {
	out, err := host.Run(ctx, "wg", "show", Iface, "listen-port")
	if err != nil {
		return 0, err
	}
	port, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 16)
	return uint16(port), err
}

// stops the tunnel and deletes its config.
func Down(ctx context.Context) error {
	if _, err := ConfigOwner(); err != nil {
		return err
	}
	if _, err := os.Stat(confPath); err == nil {
		if _, err := host.Run(ctx, "systemctl", "disable", "--now", "wg-quick@"+Iface); err != nil {
			return err
		}
	}
	return os.RemoveAll(confPath)
}

func WaitForHandshake(ctx context.Context, timeout time.Duration) bool {
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline) && ctx.Err() == nil; time.Sleep(500 * time.Millisecond) {
		handshakes, err := Handshakes(ctx)
		if err == nil && len(handshakes) > 0 {
			return true
		}
	}
	return false
}

// returns the last handshake time by peer public key.
func Handshakes(ctx context.Context) (map[string]time.Time, error) {
	if !IsUp() {
		return nil, nil
	}
	out, err := host.Run(ctx, "wg", "show", Iface, "latest-handshakes")
	if err != nil {
		return nil, err
	}
	hs := map[string]time.Time{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		key, sec, _ := strings.Cut(sc.Text(), "\t")
		if n, _ := strconv.ParseInt(sec, 10, 64); n > 0 {
			hs[key] = time.Unix(n, 0)
		}
	}
	return hs, sc.Err()
}
