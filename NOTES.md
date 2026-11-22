# Working notes — nmap / SSH capabilities

Context hand-off for continuing this work in another session (e.g. a Claude Code
session running directly on the target network). The cloud session that wrote
these files has **no route to the target network** and cannot run the tools
against live hosts — it only authored and committed them. Execution happens from
a host that is actually on the network.

## Why the split

- **Build here, run there.** The scanning/probing tools are written and version
  controlled in this repo. They must be *run* from an authorized host that can
  reach the targets (a workstation, jump box, or the broker host itself).
- This keeps everything in `robotbuzzard/security-tools` under version control
  while the live scanning happens where it legitimately can.

Scope reminder from the README: **for authorized security testing and network
administration only.** Only scan/probe hosts you administer or have permission
to test.

## What was added

- `port_scanner.rb` — wrapper around system `nmap`.
  - Connect scan (`-sT`, no root) and `-Pn` by default.
  - Default port set covers AD/Windows infra **and** MQTT: 22, 88, 135, 139,
    389, 445, 636, 1883, 3268, 3269, 3389, 5985, 5986, 8883.
  - `--version-detection` adds `-sV` (slower, noisier).
  - Parses nmap XML (`-oX -`) with stdlib REXML. Usable as a library or CLI.
- `ssh_probe.rb` — pre-auth SSH recon via `net-ssh`.
  - **Default: banner grab** (server version string). Quiet — no auth attempt.
  - `--auth-methods` enumerates offered auth methods. This *does* begin and
    abandon authentication, so it **logs a failed login on the target**. Opt-in.
- `Gemfile` — added `net-ssh ~> 7.2`.

## Decisions locked in

- Toolchain: **system `nmap` + `net-ssh` gem** (not pure-Ruby sockets).
- Defaults: connect scan, no `-sV` unless asked; SSH banner-only unless
  `--auth-methods` is passed.
- Tools are **standalone CLIs** that also work as libraries (require the file,
  use the class). They accept explicit targets or a `-f` host file.

## Needs validation on the target network

- `ssh_probe.rb` **auth-method enumeration** is best-effort: net-ssh has no
  stable public API for the server's advertised method list, so it parses the
  methods out of the `AuthenticationFailed` message. Confirm the parsed output
  against a real server before relying on it. The banner grab is reliable.

## Open / next steps (not yet done)

1. Optionally wire `find_domain_controller.rb` to chain into the scanner and SSH
   probe (discover DCs → scan → probe open 22). Currently standalone.
2. Decide whether to keep auth-method enumeration as message-parsing or move to
   a more robust approach once validated on a live server.

## How to run (on an on-network host)

```bash
bundle install            # or: gem install net-ssh net-ldap

ruby port_scanner.rb 192.168.1.111
ruby port_scanner.rb 192.168.1.0/24 --version-detection
ruby ssh_probe.rb 192.168.1.111               # banner only (quiet)
ruby ssh_probe.rb 192.168.1.111 --auth-methods  # logs a failed login on target
```

## Original question that kicked this off

Whether there's any history of an SSH connection to the MQTT broker at
**192.168.1.111**. Nothing exists in this repo or its git history. That history
lives on the hosts involved, not here:

- On the **broker (.111)** — records of *inbound* SSH:
  ```bash
  last -i | head -40
  sudo journalctl -u ssh -u sshd --no-pager | tail -60   # or: sudo grep sshd /var/log/auth.log
  cat ~/.ssh/authorized_keys
  systemctl status mosquitto 2>/dev/null; sudo ls -la /var/log/mosquitto/ 2>/dev/null
  ```
- On the **client** you connected *from* — the *outbound* trail:
  ```bash
  ssh-keygen -F 192.168.1.111            # broker host key in known_hosts?
  grep -r 192.168.1.111 ~/.ssh/ ~/.bash_history ~/.zsh_history 2>/dev/null
  ```
