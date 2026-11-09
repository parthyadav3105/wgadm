package host

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

func Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return RunWithStdin(ctx, nil, name, args...)
}

func RunWithStdin(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func InstallMissingAptPackages(ctx context.Context, packageByCommand map[string]string) error {
	var missing []string
	for command, pkg := range packageByCommand {
		if !has(command) && !slices.Contains(missing, pkg) {
			missing = append(missing, pkg)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if !has("apt-get") {
		return fmt.Errorf("install %s, then run wgadm again", strings.Join(missing, " "))
	}
	if _, err := Run(ctx, "apt-get", "update", "-qq"); err != nil {
		return err
	}
	_, err := Run(ctx, "env", append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-qq"}, missing...)...)
	return err
}

// deletes the running wgadm binary.
func RemoveExecutable() error {
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	return os.RemoveAll(bin)
}

func has(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// writes to a temp file, then renames it over path.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
