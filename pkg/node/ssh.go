package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/parthyadav3105/wgadm/pkg/host"
	"github.com/parthyadav3105/wgadm/pkg/hub"
)

var (
	ErrHubUnreachable = errors.New("cannot reach the hub")
	ErrLoginRefused   = errors.New("the hub refused this join token: it expired or was already used, create a new one on the hub with: sudo wgadm hub join-command")
	ErrRejected       = errors.New("rejected by the hub")
)

func sendJoinRequestToHub(ctx context.Context, token hub.JoinToken, req hub.JoinRequest) (hub.JoinReply, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return hub.JoinReply{}, err
	}
	out, err := sshToHubWithToken(ctx, token, body)
	if err != nil {
		return hub.JoinReply{}, err
	}

	var reply hub.JoinReply
	if err := json.Unmarshal(out, &reply); err != nil {
		return hub.JoinReply{}, fmt.Errorf("unexpected reply from the hub: %q", out)
	}
	if reply.Error != "" {
		return hub.JoinReply{}, fmt.Errorf("%w: %s", ErrRejected, reply.Error)
	}
	return reply, nil
}

// logs in with the token's key, the hub's forced command reads stdin.
func sshToHubWithToken(ctx context.Context, token hub.JoinToken, stdin []byte) ([]byte, error) {
	knownHosts, err := pinnedKnownHosts(ctx, token)
	if err != nil {
		return nil, err
	}
	defer os.Remove(knownHosts)

	keyFile, err := writeTempFile("wgadm-join-key-*", token.PrivateKey)
	if err != nil {
		return nil, err
	}
	defer os.Remove(keyFile)

	cmd := exec.CommandContext(ctx, "ssh", "-T", "-p", token.SSHPort,
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile="+knownHosts,
		"-i", keyFile,
		hub.JoinUser+"@"+token.Host)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok && exitErr.ExitCode() == 255 {
		if strings.Contains(stderr.String(), "Permission denied") {
			return nil, ErrLoginRefused
		}
		return nil, fmt.Errorf("%w: %s", ErrHubUnreachable, strings.TrimSpace(stderr.String()))
	}
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %w: %s", token.Host, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// returns a temp known_hosts file with only the hub keys matching the token's fingerprint.
func pinnedKnownHosts(ctx context.Context, token hub.JoinToken) (string, error) {
	keys, err := host.Run(ctx, "ssh-keyscan", "-T", "5", "-p", token.SSHPort, token.Host)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrHubUnreachable, err)
	}

	var pinned []string
	for line := range strings.Lines(string(keys)) {
		out, err := host.RunWithStdin(ctx, []byte(line), "ssh-keygen", "-lf", "-")
		if err == nil && slices.Contains(strings.Fields(string(out)), token.SSHFingerprint) {
			pinned = append(pinned, strings.TrimSpace(line))
		}
	}
	if len(pinned) == 0 {
		return "", fmt.Errorf("host key of %s does not match the join token", token.Host)
	}
	return writeTempFile("wgadm-known-hosts-*", strings.Join(pinned, "\n")+"\n")
}

func writeTempFile(pattern, content string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
