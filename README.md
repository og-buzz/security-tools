# Security Tools

A small collection of Ruby-based tools for authorized network administration and
security testing.

- **`find_domain_controller.rb`** — discovers Active Directory domain controllers.
- **`port_scanner.rb`** — structured `nmap` wrapper (AD/Windows + MQTT port set).
- **`ssh_probe.rb`** — pre-auth SSH recon (banner grab, optional auth-method enum).

See `NOTES.md` for design decisions and the build/run split.

---

## Active Directory Domain Controller Discovery Tool

A Ruby-based tool for discovering Active Directory domain controllers on a network.

## Features

- Multiple discovery methods (DNS SRV, common names, environment variables)
- LDAP connectivity verification
- Detailed reporting of discovered controllers
- Network troubleshooting hints

## Installation

```bash
gem install net-ldap
```

## Usage

```bash
ruby find_domain_controller.rb
```

## Discovery Methods

1. **DNS SRV Records** - Queries standard AD SRV records
2. **Common Hostnames** - Checks typical DC naming patterns
3. **Environment Variables** - Examines system environment for DC information
4. **DNS A Records** - Looks up common LDAP-related DNS entries

## Requirements

- Ruby 3.0+
- net-ldap gem

## Use Cases

- Network administration
- Security auditing
- AD connectivity troubleshooting
- Domain controller inventory

---

## Port Scanner

Wraps the system `nmap` and returns structured results. TCP connect scan
(`-sT`, no root) with host discovery disabled (`-Pn`) by default.

```bash
ruby port_scanner.rb 192.168.1.111
ruby port_scanner.rb 192.168.1.0/24
ruby port_scanner.rb -p 22,1883,8883 192.168.1.111
ruby port_scanner.rb --version-detection 192.168.1.111   # adds nmap -sV
ruby port_scanner.rb -f hosts.txt
```

Requires `nmap` on PATH. Default ports cover AD/Windows infrastructure and MQTT
(22, 88, 135, 139, 389, 445, 636, 1883, 3268, 3269, 3389, 5985, 5986, 8883).

## SSH Probe

Pre-authentication reconnaissance of an SSH service via `net-ssh`.

```bash
ruby ssh_probe.rb 192.168.1.111                  # banner grab only (quiet)
ruby ssh_probe.rb 192.168.1.111 --auth-methods   # enumerate auth methods
ruby ssh_probe.rb -p 2222 host-a host-b
```

- **Banner grab (default)** reads the server version string; no authentication
  is attempted.
- **`--auth-methods`** begins and abandons authentication to learn the offered
  methods. This normally **records a failed login on the target** — opt-in only.

Requires the `net-ssh` gem (`gem install net-ssh` or `bundle install`).

## License

For authorized security testing and network administration only.