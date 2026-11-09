package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/parthyadav3105/wgadm/pkg/hub"
	"github.com/parthyadav3105/wgadm/pkg/node"
	"github.com/parthyadav3105/wgadm/pkg/wireguard"
)

func newNodeCmd() *cobra.Command {
	cmd := group("node", "Connect this machine to a hub",
		newNodeJoinCmd(),
	)
	cmd.Hidden = true
	cmd.PersistentPreRunE = requireRoot
	return cmd
}

func newNodeJoinCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:     "join <token>",
		Short:   "Join this machine to the hub with a token from 'hub join-command'",
		Example: "  sudo wgadm node join eyJob3N0Ijoi... --name nas",
		Args:    usage(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := hub.ParseJoinToken(args[0])
			if err != nil {
				return usageError{err}
			}
			if name == "" {
				h, err := os.Hostname()
				if err != nil {
					return err
				}
				name, _, _ = strings.Cut(strings.ToLower(h), ".")
			}

			ip, err := node.Join(cmd.Context(), token, name)
			if errors.Is(err, node.ErrRejected) && strings.Contains(err.Error(), hub.ErrNameTaken.Error()) {
				return fmt.Errorf("%w\nchoose another --name, or if this is the same machine run 'wgadm hub peer rm %s' on the hub, then join again", err, name)
			}
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if !wireguard.WaitForHandshake(cmd.Context(), 10*time.Second) {
				fmt.Fprintf(w, "joined as %s %s, but no handshake with the hub yet\n", name, ip)
				fmt.Fprintln(w, "check that the hub's cloud firewall allows its WireGuard UDP port and that its DNS name is correct")
				return nil
			}
			fmt.Fprintf(w, "joined as %s %s, connected to the hub\n", name, ip)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "peer name shown on the hub (default: hostname)")
	return cmd
}
