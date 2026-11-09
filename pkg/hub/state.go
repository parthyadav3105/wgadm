package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"

	"github.com/parthyadav3105/wgadm/pkg/host"
)

const statePath = "/etc/wireguard/wgadm/state.json"

type state struct {
	Endpoint   string       `json:"endpoint"`
	Port       uint16       `json:"port"`
	Subnet     netip.Prefix `json:"subnet"`
	PrivateKey string       `json:"privateKey"`
	PublicKey  string       `json:"publicKey"`
	JoinTokens []joinToken  `json:"joinTokens,omitempty"`
	Peers      []peer       `json:"peers"`
	Held       []hold       `json:"held,omitempty"`
}

func loadState(path string) (*state, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return &s, nil
}

func (s *state) save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return host.WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// loads the state, runs change and saves the result while holding the state directory lock.
func changeStateUnderLock(change func(*state) error) error {
	dir := filepath.Dir(statePath)
	d, err := os.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotInitialized
	}
	if err != nil {
		return err
	}
	defer d.Close()
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock %s: %w", dir, err)
	}

	s, err := loadState(statePath)
	if err != nil {
		return err
	}
	if err := change(s); err != nil {
		return err
	}
	return s.save(statePath)
}
