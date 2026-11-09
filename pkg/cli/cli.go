package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/parthyadav3105/wgadm/pkg/hub"
	"github.com/parthyadav3105/wgadm/pkg/node"
	"github.com/parthyadav3105/wgadm/pkg/wireguard"
)

const (
	exitOK          = 0
	exitError       = 1
	exitUsage       = 2
	exitWrongRole   = 3
	exitAlreadyDone = 4
	exitUnreachable = 5
	exitRejected    = 6
)

type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }

func Run(ctx context.Context) int {
	err := newRootCmd().ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	fmt.Fprintf(os.Stderr, "wgadm: %v\n", err)
	switch {
	case errors.As(err, new(usageError)):
		return exitUsage
	case errors.Is(err, hub.ErrNotInitialized):
		fmt.Fprintln(os.Stderr, "run this on the hub (to create a hub: wgadm hub init)")
		return exitWrongRole
	case errors.Is(err, node.ErrNotJoined):
		fmt.Fprintln(os.Stderr, "run this on a joined machine (to join: wgadm node join <token>)")
		return exitWrongRole
	case errors.Is(err, hub.ErrAlreadyInitialized), errors.Is(err, node.ErrAlreadyJoined):
		return exitAlreadyDone
	case errors.Is(err, node.ErrHubUnreachable):
		return exitUnreachable
	case errors.Is(err, hub.ErrNameTaken), errors.Is(err, hub.ErrSubnetFull), errors.Is(err, node.ErrRejected), errors.Is(err, node.ErrLoginRefused):
		return exitRejected
	}
	return exitError
}

func newRootCmd() *cobra.Command {
	cobra.EnableCommandSorting = false
	root := group("wgadm", "Build a private WireGuard network: one hub, with your machines and phones connected to it",
		newHubCmd(),
		newNodeCmd(),
		newStatusCmd(),
		newUninstallCmd(),
		newVersionCmd(),
	)
	root.SilenceUsage = true
	root.SilenceErrors = true
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError{err} })
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if cmd == root {
			printRootHelp(cmd.OutOrStdout(), root)
			return
		}
		defaultHelp(cmd, args)
	})
	return root
}

func printRootHelp(w io.Writer, root *cobra.Command) {
	var hubCommands, commonCommands []*cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "hub" {
			hubCommands = visibleLeafCommands(c)
		} else if c.IsAvailableCommand() {
			commonCommands = append(commonCommands, c)
		}
	}

	commandName := func(c *cobra.Command) string { return strings.TrimPrefix(c.CommandPath(), root.Name()+" ") }
	width := 0
	for _, c := range append(slices.Clone(hubCommands), commonCommands...) {
		width = max(width, len(commandName(c)))
	}
	printSection := func(title string, commands []*cobra.Command) {
		fmt.Fprintf(w, "%s:\n", title)
		for _, c := range commands {
			fmt.Fprintf(w, "  %-*s  %s\n", width, commandName(c), c.Short)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%s\n\nUsage:\n  %s <command>\n\n", root.Short, root.Name())
	printSection("Hub Commands", hubCommands)
	printSection("Common Commands", commonCommands)
	fmt.Fprintf(w, "Use \"%s <command> --help\" for more information about a command.\n", root.Name())
}

func visibleLeafCommands(cmd *cobra.Command) []*cobra.Command {
	if !cmd.HasAvailableSubCommands() {
		return []*cobra.Command{cmd}
	}
	var leaves []*cobra.Command
	for _, c := range cmd.Commands() {
		if c.IsAvailableCommand() {
			leaves = append(leaves, visibleLeafCommands(c)...)
		}
	}
	return leaves
}

func group(use, short string, children ...*cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  usage(cobra.NoArgs),
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(children...)
	return cmd
}

// marks argument errors so they exit with exitUsage.
func usage(validate cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := validate(cmd, args); err != nil {
			return usageError{err}
		}
		return nil
	}
}

// group commands only print help, so they work without root.
func requireRoot(cmd *cobra.Command, _ []string) error {
	if cmd.HasSubCommands() {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("must run as root (use sudo)")
	}
	return nil
}

func newStatusCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:     "status",
		Short:   "Show tunnel and peer health on this machine",
		Args:    usage(cobra.NoArgs),
		PreRunE: requireRoot,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output != "table" && output != "json" {
				return usageError{fmt.Errorf("invalid --output %q: use table or json", output)}
			}
			w := cmd.OutOrStdout()
			info, err := hub.Local.Status(cmd.Context())
			if err == nil {
				if output == "json" {
					return json.NewEncoder(w).Encode(map[string]any{"hub": info})
				}
				printHubStatus(w, info)
				return nil
			}
			if !errors.Is(err, hub.ErrNotInitialized) {
				return err
			}

			n, err := node.Status(cmd.Context())
			if err != nil {
				return err
			}
			if output == "json" {
				return json.NewEncoder(w).Encode(map[string]any{"node": n})
			}
			printNodeStatus(w, n)
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table|json")
	return cmd
}

func printHubStatus(w io.Writer, info hub.Info) {
	fmt.Fprintf(w, "hub %s:%d  subnet %s\n\n", info.Endpoint, info.Port, info.Subnet)
	printPeers(w, info.Peers)
	if len(info.Peers) == 0 {
		fmt.Fprintln(w, "no peers yet. To join a machine, run: sudo wgadm hub join-command")
	}
	if !info.Up {
		fmt.Fprintf(w, "warning: %s is down\n", wireguard.Iface)
	}
}

func printNodeStatus(w io.Writer, n node.Info) {
	fmt.Fprintf(w, "node %s  hub %s\nlast handshake: %s\n", n.IP, n.Hub, ago(time.Now(), n.LastHandshake))
	if !n.Up {
		fmt.Fprintf(w, "warning: %s is down\n", wireguard.Iface)
	}
	if n.LastHandshake.IsZero() {
		fmt.Fprintln(w, "no handshake with the hub yet. Check that the hub's cloud firewall allows its WireGuard UDP port and that its DNS name is correct")
	} else if time.Since(n.LastHandshake) > 3*time.Minute {
		fmt.Fprintln(w, "no recent handshake with the hub. If it removed this machine, clean up with: wgadm uninstall")
	}
}

func newUninstallCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "uninstall",
		Short:   "Remove everything wgadm added to this machine, including itself",
		Args:    usage(cobra.NoArgs),
		PreRunE: requireRoot,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			info, err := hub.Local.Status(cmd.Context())
			if errors.Is(err, hub.ErrNotInitialized) {
				if !yes && !confirmed(cmd, "This removes this machine's tunnel and wgadm. If you are connected over the VPN, you will lose this session.\nType yes to continue: ", "yes") {
					return errors.New("aborted")
				}
				if err := node.Uninstall(cmd.Context()); err != nil {
					return err
				}
				fmt.Fprintln(w, "wgadm removed. To finish, run on the hub: sudo wgadm hub peer rm <name>")
				return nil
			}
			if err != nil {
				return err
			}

			prompt := fmt.Sprintf("This removes the hub and disconnects all peers (%d). It cannot be undone without a 'wgadm hub backup'.\nType the endpoint (%s) to continue: ", len(info.Peers), info.Endpoint)
			if !yes && !confirmed(cmd, prompt, info.Endpoint) {
				return errors.New("aborted")
			}
			if err := hub.Local.Uninstall(cmd.Context()); err != nil {
				return err
			}
			fmt.Fprintln(w, "hub removed")
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}

func confirmed(cmd *cobra.Command, prompt, answer string) bool {
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	return strings.TrimSpace(line) == answer
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the wgadm version",
		Args:  usage(cobra.NoArgs),
		Run: func(cmd *cobra.Command, _ []string) {
			version := "unknown"
			if info, ok := debug.ReadBuildInfo(); ok {
				version = info.Main.Version
			}
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}
}

type duration time.Duration

func (d *duration) Type() string { return "duration" }

func (d *duration) String() string {
	if *d == 0 {
		return ""
	}
	return time.Duration(*d).String()
}

func (d *duration) Set(s string) error {
	v, err := time.ParseDuration(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		var n int
		n, err = strconv.Atoi(days)
		v = time.Duration(n) * 24 * time.Hour
	}
	if err != nil || v <= 0 {
		return errors.New("use a positive duration like 90d or 12h")
	}
	*d = duration(v)
	return nil
}

func ago(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	switch d := now.Sub(t); {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
