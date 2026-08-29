# Wakora Agent

The monitoring agent behind [Wakora](https://www.wakora.io). One static Go binary, no
configuration file to write, one outbound connection. This repository is public so that
the people whose servers it runs on can read exactly what it does.

## Install

```bash
curl -fsSL https://get.wakora.io | bash -s -- --key <WORKSPACE_KEY>
```

The key comes from your workspace under Settings, Agent keys. The installer detects the
platform, verifies the download against a signed manifest, installs the service and
registers the host. Nothing else is asked of you: the agent finds the services on the box
by itself.

Windows uses the same flow through PowerShell, see
[the install guide](https://docs.wakora.io/getting-started/installation).

## What it does

It reports host metrics (CPU, memory, disk, load, network, uptime) every 60 seconds and a
heartbeat every 30, then goes looking for what else is worth watching: running processes,
listening ports, installed packages, service units, cron entries. When a service is
recognised, the platform sends down a signed definition describing how to probe it, and
the agent starts collecting real numbers for that service rather than a generic process
check. Adding support for a new service does not need a new agent release.

On top of that it can collect application traces and CPU profiles for PHP, .NET and
Node.js, browser timings, container and Kubernetes telemetry, full logs with host-side
filtering, and SNMP from network devices when a host is given a collector role.

## Design decisions worth knowing about

**One outbound connection.** The agent dials the platform over TLS and keeps a WebSocket
open. Nothing listens for inbound traffic, so it works behind NAT with no firewall holes
and no port forwarding. The server never dials the agent.

**The certificate is pinned.** The endpoint and a SHA-256 of the server's public key are
compiled into the binary. A TLS-inspecting proxy in the path will break the connection by
design, and the agent refuses to start if a release build has no pin.

**Definitions are signed.** Anything that tells the agent to run a command, a query or an
HTTP request is verified against an ed25519 public key baked into the binary. There is no
unsigned path. `exec` is restricted to an allow-list of binaries and never goes through a
shell.

**Credentials stay on the host.** A definition refers to a credential by name; the value
lives in an encrypted local store and is resolved at probe time. Passwords never travel to
the server, which is the point rather than a detail. Command lines and log lines are
redacted on the host before anything is sent.

**It does not restart your services.** A change that would only take effect after a reload
(enabling a tracing extension, for example) is written, marked as pending, and reported
with the exact command and its impact. A human runs it. The agent then notices the change
took effect. The only service it ever restarts is its own, during a self-update.

**It stays small.** Measured on a production cadence: about 0.1% of one core and 5 MB
resident. The heap is capped in-process and the service is configured so that under memory
pressure the kernel kills the agent before it kills anything of yours.

**Updates are signed and cannot go backwards.** The agent fetches a manifest, verifies its
signature, verifies the binary's own signature, refuses anything older than what it is
running, and refuses a manifest older than the last one it accepted. A host can be pinned
to an exact version instead.

## Platforms

| | amd64 | arm64 |
|---|---|---|
| Linux (systemd, OpenRC, sysvinit; glibc and musl) | yes | yes |
| Windows (service) | yes | yes |
| macOS (launchd) | yes | yes |

Deep probes that need kernel privileges (eBPF request tracking) run where the kernel
allows them and fall back to log-derived numbers where it does not, for example in an
unprivileged container.

## Build from source

```bash
go build ./cmd/wakora
```

That produces a working binary with no endpoint, which is only useful for reading and
testing. Release builds get their endpoint, certificate pin and publisher key at link time:

```bash
go build -ldflags "\
  -X wakora.io/agent/internal/buildinfo.Version=dev \
  -X wakora.io/agent/internal/buildinfo.Endpoint=wss://<host>/ws \
  -X wakora.io/agent/internal/buildinfo.CertPin=<base64 sha256 of the server SPKI> \
  -X wakora.io/agent/internal/buildinfo.PublisherKey=<base64 ed25519 public key>" \
  ./cmd/wakora
```

Go 1.25 or newer. No cgo, no external build tools. The macOS build gains a few extra
metrics when built with cgo on a Mac.

## Diagnosing a host

```bash
wakora doctor          # checks identity, connectivity, pin, service state, permissions
wakora --test          # collect once and print, without sending
wakora secret set <n>  # store a credential locally
wakora uninstall       # remove the service, the state and the binary
```

Its own log is at `/var/log/wakora/agent.log` on Linux.

## Documentation

Full reference at [docs.wakora.io](https://docs.wakora.io): every metric it emits, every
service in the catalog, the security model, and the operational side.

## Security

Found something? security@wakora.io. Please do not open a public issue for a
vulnerability. Details and our PGP key are at <https://www.wakora.io/security>.

## License

[Elastic License 2.0](LICENSE). Read it, run it, modify it, deploy it on machines you
control. The one thing it does not allow is offering it to third parties as a hosted or
managed service.

That applies to anyone who takes the source from here. Commercial arrangements, including
partner and reseller terms, are separate agreements and are not affected by it.
