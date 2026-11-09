package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"text/tabwriter"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/spf13/cobra"

	"github.com/parthyadav3105/wgadm/pkg/hub"
	"github.com/parthyadav3105/wgadm/pkg/wireguard"
)

const defaultJoinTokenTTL = 15 * time.Minute

func newHubCmd() *cobra.Command {
	cmd := group("hub", "Set up and manage the hub",
		newHubInitCmd(),
		newHubJoinCommandCmd(),
		group("peer", "Add, list and remove peers",
			newHubPeerAddCmd(),
			newHubPeerLsCmd(),
			newHubPeerRmCmd(),
		),
		newHubBackupCmd(),
		newHubRestoreCmd(),
		newHubServeJoinCmd(),
	)
	cmd.PersistentPreRunE = requireRoot
	return cmd
}

func newHubInitCmd() *cobra.Command {
	var endpoint, subnet string
	var port uint16
	cmd := &cobra.Command{
		Use:     "init",
		Short:   "Make this machine the hub",
		Example: "  sudo wgadm hub init --endpoint vpn.example.com",
		Args:    usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if endpoint == "" {
				return usageError{errors.New("--endpoint is required")}
			}
			if port == 0 {
				return usageError{errors.New("--port must be 1-65535")}
			}
			prefix, err := netip.ParsePrefix(subnet)
			if err != nil {
				return usageError{fmt.Errorf("invalid --subnet: %w", err)}
			}
			info, err := hub.Local.Init(cmd.Context(), endpoint, port, prefix)
			if err != nil {
				return err
			}
			printInit(cmd.OutOrStdout(), info)
			token, err := hub.Local.CreateJoinToken(cmd.Context(), defaultJoinTokenTTL)
			if err != nil {
				return fmt.Errorf("the hub is up, but its join command could not be created: %w\nonce that is fixed, run: sudo wgadm hub join-command", err)
			}
			printJoinCommand(cmd.OutOrStdout(), token, defaultJoinTokenTTL)
			return nil
		},
	}
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "public DNS name or IP of this hub")
	cmd.Flags().Uint16Var(&port, "port", 51820, "WireGuard UDP port")
	cmd.Flags().StringVar(&subnet, "subnet", "10.66.0.0/24", "VPN subnet")
	return cmd
}

func printInit(w io.Writer, info hub.Info) {
	fmt.Fprintf(w, "hub is up: %s %s udp/%d\n\n", wireguard.Iface, info.Address, info.Port)
	fmt.Fprintf(w, "Still to do by hand:\n  - Cloud firewall: allow inbound UDP %d, and SSH from the machines that will join.\n", info.Port)
	if _, err := netip.ParseAddr(info.Endpoint); err != nil {
		fmt.Fprintf(w, "  - DNS: point %s at this VM. On Cloudflare use \"DNS only\".\n", info.Endpoint)
	}
	fmt.Fprintln(w)
}

func printJoinCommand(w io.Writer, token hub.JoinToken, validFor time.Duration) {
	fmt.Fprintf(w, "Join one machine (works once, valid for %s):\n  sudo wgadm node join %s\n", validFor, token)
}

func newHubJoinCommandCmd() *cobra.Command {
	ttl := defaultJoinTokenTTL
	cmd := &cobra.Command{
		Use:   "join-command",
		Short: "Print a single-use command that joins one machine",
		Args:  usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			token, err := hub.Local.CreateJoinToken(cmd.Context(), ttl)
			if err != nil {
				return err
			}
			printJoinCommand(cmd.OutOrStdout(), token, ttl)
			return nil
		},
	}
	cmd.Flags().Var((*duration)(&ttl), "ttl", "how long the command stays valid, e.g. 1h")
	return cmd
}

func newHubBackupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "backup <file>",
		Short: "Write the hub's keys and peers to a file",
		Args:  usage(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := hub.Local.Backup(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "backup written to %s, it contains the hub's private key\n", args[0])
			return nil
		},
	}
}

func newHubRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restore <file>",
		Short: "Rebuild the hub from a backup",
		Args:  usage(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			info, err := hub.Local.Restore(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			printInit(cmd.OutOrStdout(), info)
			fmt.Fprintln(cmd.OutOrStdout(), "To join a machine: sudo wgadm hub join-command")
			return nil
		},
	}
}

func newHubPeerLsCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List all peers",
		Args:  usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output != "table" && output != "json" {
				return usageError{fmt.Errorf("invalid --output %q: use table or json", output)}
			}
			info, err := hub.Local.Status(cmd.Context())
			if err != nil {
				return err
			}
			if output == "json" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(info.Peers)
			}
			printPeers(cmd.OutOrStdout(), info.Peers)
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table|json")
	return cmd
}

func printPeers(w io.Writer, peers []hub.PeerStatus) {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "NAME\tKIND\tIP\tLAST HANDSHAKE")
	now := time.Now()
	for _, p := range peers {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, p.Kind, p.IP, ago(now, p.LastHandshake))
	}
	tw.Flush()
}

func newHubPeerAddCmd() *cobra.Command {
	var pubkey string
	var qr bool
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a phone or other WireGuard app device",
		Args:  usage(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if pubkey != "" && qr {
				return usageError{errors.New("--pubkey and --qr cannot be used together")}
			}
			privateKey, publicKey := "<private key of this device>", pubkey
			if pubkey == "" {
				var err error
				if privateKey, publicKey, err = wireguard.GenerateKey(); err != nil {
					return err
				}
			}
			p, cfg, err := hub.Local.AddAppDevice(cmd.Context(), args[0], publicKey)
			if err != nil {
				return err
			}
			cfg.PrivateKey = privateKey
			conf := string(cfg.Render())

			w := cmd.OutOrStdout()
			fmt.Fprintf(cmd.ErrOrStderr(), "added %s (%s) %s\n", p.Name, p.Kind, p.IP)
			fmt.Fprintln(cmd.ErrOrStderr(), "import this into the WireGuard app. It is shown only once")
			if !qr && pubkey == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "to scan a QR code instead, remove this peer and add it again with --qr")
			}
			if qr {
				qrterminal.GenerateHalfBlock(conf, qrterminal.L, w)
			} else {
				fmt.Fprint(w, conf)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&pubkey, "pubkey", "", "register this public key instead of generating one")
	cmd.Flags().BoolVar(&qr, "qr", false, "print the config as a QR code")
	return cmd
}

func newHubPeerRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "Revoke a peer immediately",
		Args:  usage(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := hub.Local.RemovePeer(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "revoked %s (%s)\n", p.Name, p.IP)
			return nil
		},
	}
}

func newHubServeJoinCmd() *cobra.Command {
	var tokenID string
	cmd := &cobra.Command{
		Use:    "serve-join",
		Hidden: true,
		Args:   usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			var req hub.JoinRequest
			var reply hub.JoinReply
			err := json.NewDecoder(io.LimitReader(cmd.InOrStdin(), 64<<10)).Decode(&req)
			if err == nil {
				reply, err = hub.Local.JoinNode(cmd.Context(), tokenID, req)
			}
			if err != nil {
				reply = hub.JoinReply{Error: err.Error()}
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(reply)
		},
	}
	cmd.Flags().StringVar(&tokenID, "token-id", "", "join token this login was made with")
	return cmd
}
