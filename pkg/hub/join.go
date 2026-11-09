package hub

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/parthyadav3105/wgadm/pkg/host"
)

// the hub's record of a token, the private key is only ever given to the admin.
type joinToken struct {
	ID        string    `json:"id"`
	PublicKey string    `json:"publicKey"`
	Expires   time.Time `json:"expires"`
}

func (localHub) CreateJoinToken(ctx context.Context, validFor time.Duration) (JoinToken, error) {
	var token JoinToken
	err := changeStateAndApply(ctx, func(s *state) error {
		fingerprint, err := sshHostFingerprint(ctx)
		if err != nil {
			return err
		}
		privateKey, publicKey, err := newSSHKeyPair(ctx)
		if err != nil {
			return err
		}
		id := make([]byte, 8)
		rand.Read(id)

		s.JoinTokens = append(s.JoinTokens, joinToken{ID: hex.EncodeToString(id), PublicKey: publicKey, Expires: time.Now().UTC().Add(validFor)})
		token = JoinToken{Host: s.Endpoint, SSHPort: sshPort(ctx), PrivateKey: privateKey, SSHFingerprint: fingerprint}
		return setupJoinUser(ctx, s.JoinTokens)
	})
	return token, err
}

func (localHub) JoinNode(ctx context.Context, tokenID string, req JoinRequest) (JoinReply, error) {
	var reply JoinReply
	err := changeStateAndApply(ctx, func(s *state) error {
		i := slices.IndexFunc(s.JoinTokens, func(t joinToken) bool { return t.ID == tokenID })
		if i < 0 {
			return errors.New("join token expired or already used")
		}
		s.JoinTokens = slices.Delete(s.JoinTokens, i, i+1)

		p, err := s.addPeer(peer{Name: req.Name, Kind: kindNode, PublicKey: req.PublicKey})
		if err != nil {
			return err
		}
		reply = JoinReply{IP: p.IP, Subnet: s.Subnet, Endpoint: s.endpointWithPort(), HubPublicKey: s.PublicKey}
		return setupJoinUser(ctx, s.JoinTokens)
	})
	return reply, err
}

func (t JoinToken) String() string {
	data, _ := json.Marshal(t)
	return base64.RawURLEncoding.EncodeToString(data)
}

func ParseJoinToken(text string) (JoinToken, error) {
	invalid := errors.New("invalid join token, create one on the hub with: sudo wgadm hub join-command")
	data, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return JoinToken{}, invalid
	}
	var t JoinToken
	if err := json.Unmarshal(data, &t); err != nil {
		return JoinToken{}, invalid
	}
	if _, err := strconv.ParseUint(t.SSHPort, 10, 16); err != nil || !ValidEndpoint(t.Host) || t.PrivateKey == "" || !strings.HasPrefix(t.SSHFingerprint, "SHA256:") {
		return JoinToken{}, invalid
	}
	return t, nil
}

func sshHostFingerprint(ctx context.Context) (string, error) {
	out, err := host.Run(ctx, "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		return "", err
	}
	if f := strings.Fields(string(out)); len(f) > 1 {
		return f[1], nil
	}
	return "", errors.New("cannot read the SSH host key fingerprint")
}

// returns the port sshd listens on, 22 if sshd cannot say.
func sshPort(ctx context.Context) string {
	// sshd -T refuses to run without this directory, which is missing while ssh is stopped.
	os.MkdirAll("/run/sshd", 0o755)
	out, err := host.Run(ctx, "sshd", "-T")
	if err != nil {
		return "22"
	}
	for line := range strings.Lines(string(out)) {
		if port, ok := strings.CutPrefix(strings.TrimSpace(line), "port "); ok {
			return port
		}
	}
	return "22"
}

func newSSHKeyPair(ctx context.Context) (privateKey, publicKey string, err error) {
	dir, err := os.MkdirTemp("", "wgadm-join-key-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(dir)

	keyFile := filepath.Join(dir, "key")
	if _, err := host.Run(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", JoinUser, "-f", keyFile); err != nil {
		return "", "", err
	}
	private, err := os.ReadFile(keyFile)
	if err != nil {
		return "", "", err
	}
	public, err := os.ReadFile(keyFile + ".pub")
	if err != nil {
		return "", "", err
	}
	return string(private), strings.TrimSpace(string(public)), nil
}

// lets each live token's key log in, sshd itself refuses a key after its expiry.
func setupJoinUser(ctx context.Context, tokens []joinToken) error {
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		return err
	}
	if err := checkRootOwned(bin); err != nil {
		return err
	}
	u, err := ensureJoinUser(ctx)
	if err != nil {
		return err
	}

	lines := make([]string, len(tokens))
	for i, t := range tokens {
		lines[i] = fmt.Sprintf(`restrict,expiry-time="%s",command="sudo -n %s hub serve-join --token-id %s" %s`, t.Expires.UTC().Format("20060102150405Z"), bin, t.ID, t.PublicKey)
	}
	if err := writeAuthorizedKeys(u, lines); err != nil {
		return err
	}
	return writeSudoers(ctx, fmt.Sprintf("%s ALL=(root) NOPASSWD: %s hub serve-join --token-id *", JoinUser, bin))
}

// fails unless path and every parent are owned by root and not writable by others.
func checkRootOwned(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s must be owned by root and not writable by group or others", p)
		}
		if p == "/" {
			return nil
		}
	}
}

func ensureJoinUser(ctx context.Context) (*user.User, error) {
	if u, err := user.Lookup(JoinUser); err == nil {
		return u, nil
	}
	if _, err := host.Run(ctx, "useradd", "--system", "--create-home", "--shell", "/bin/sh", "--password", "*", JoinUser); err != nil {
		return nil, err
	}
	return user.Lookup(JoinUser)
}

func writeAuthorizedKeys(u *user.User, lines []string) error {
	dir := filepath.Join(u.HomeDir, ".ssh")
	for _, d := range []string{u.HomeDir, dir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
		if err := os.Chown(d, 0, 0); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o755); err != nil {
			return err
		}
	}
	return host.WriteFileAtomic(filepath.Join(dir, "authorized_keys"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func writeSudoers(ctx context.Context, rule string) error {
	path := "/etc/sudoers.d/" + JoinUser
	if err := os.WriteFile(path, []byte(rule+"\n"), 0o440); err != nil {
		return err
	}
	if _, err := host.Run(ctx, "visudo", "-cqf", path); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func removeJoinUser(ctx context.Context) error {
	if err := os.RemoveAll("/etc/sudoers.d/" + JoinUser); err != nil {
		return err
	}
	u, err := user.Lookup(JoinUser)
	if err != nil {
		return nil
	}
	if _, err := host.Run(ctx, "userdel", JoinUser); err != nil {
		return err
	}
	return os.RemoveAll(u.HomeDir)
}
