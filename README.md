# wgadm

**Connect your machines into one private WireGuard network with a single command.**

wgadm automates creating a [WireGuard](https://www.wireguard.com/) network: each machine gets a fixed IP, and all of them join one publicly reachable **hub** machine.

wgadm configures WireGuard and then exits. Nothing of wgadm runs in the background.

```
                 hub  vpn.example.com  10.66.0.1
                              │
        ┌──────────────┬──────┴───────┬──────────────┐
       nas          gpu-box       laptop        alice-phone
   10.66.0.10     10.66.0.11    10.66.0.12      10.66.0.200
```

- **node**: a Linux machine that joins with `wgadm node join`.
- **app**: a phone or other device using the official WireGuard app, added with `wgadm hub peer add`.

Only traffic for the VPN subnet goes through the hub. Everything else uses the device's normal connection.

## Install

On the hub and on every node:

```bash
sudo curl -fsSL https://github.com/parthyadav3105/wgadm/releases/latest/download/wgadm-linux-$(uname -m) \
  -o /usr/local/bin/wgadm
sudo chmod 755 /usr/local/bin/wgadm
```

wgadm installs WireGuard itself on Debian and Ubuntu. On other distributions, install `wireguard-tools` first.

## Quick start

**1. Set up the hub** on a machine the others can reach:

```bash
sudo wgadm hub init --endpoint <dns-name-or-public-ip>
```

`--endpoint` is the address other machines use to reach the hub. Prefer a DNS name: with a plain IP, every machine has to join again if it changes.

It prints what is left to do, and the command to join a machine:

```
hub is up: vpn0 10.66.0.1/24 udp/51820

Still to do by hand:
  - Cloud firewall: allow inbound UDP 51820, and SSH from the machines that will join.
  - DNS: point vpn.example.com at this VM. On Cloudflare use "DNS only".

Join one machine (works once, valid for 15m0s):
  sudo wgadm node join <token>
```

**2. Join a machine** by running the printed command on it. Add `--name nas` to name it, otherwise it uses its hostname.

To join another machine, get a new command on the hub at any time:

```bash
sudo wgadm hub join-command [--ttl 1h]
```

Keep the token private until it's used.

**3. Add a phone** on the hub, then scan the QR code in the WireGuard app:

```bash
sudo wgadm hub peer add alice-phone --qr
```

**4. Check:**

```bash
sudo wgadm status
```

```
hub vpn.example.com:51820  subnet 10.66.0.0/24

NAME          KIND   IP            LAST HANDSHAKE
nas           node   10.66.0.10    12s ago
alice-phone   app    10.66.0.200   never
```

Now `ssh you@10.66.0.10` works from the hub and from any other peer.

**Permanent addresses:** a peer keeps its IP for as long as it exists. After it is removed, that IP is held back for 90 days, and a machine that joins again gets a new one.

## Removing machines and uninstalling

- Retire a machine: `sudo wgadm uninstall` on the machine (asks first; `--yes` skips that), then `sudo wgadm hub peer rm <name>` on the hub.
- Shut down the whole VPN: `sudo wgadm uninstall` on the hub. It asks you to type the endpoint; run `wgadm hub backup` first if you may need it.

For a phone, run `wgadm hub peer rm <name>` on the hub and delete the tunnel in the WireGuard app.

`uninstall` removes everything wgadm added, including its own binary. The WireGuard package itself stays installed.

## Command reference

```
wgadm hub init --endpoint <host> [--port 51820] [--subnet 10.66.0.0/24]
wgadm hub join-command [--ttl 15m]
wgadm hub backup <file>
wgadm hub restore <file>
wgadm hub peer ls [-o table|json]
wgadm hub peer add <name> [--pubkey <key>] [--qr]
wgadm hub peer rm <name>

wgadm node join <token> [--name <name>]

wgadm status [-o table|json]
wgadm uninstall [--yes]
wgadm version
wgadm completion bash|zsh|fish|powershell
```
