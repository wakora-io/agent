# Reporting a vulnerability

Email **security@wakora.io**. Please do not open a public issue for a vulnerability, and
please do not disclose it publicly before a fix is out.

Our PGP key and fingerprint are published at <https://www.wakora.io/security>, and the
same contact is in our `security.txt`. Encrypt if the report contains anything sensitive.

## What to expect

| | target |
|---|---|
| acknowledgement | 1 business day |
| triage and initial assessment | 3 business days |
| fix for a critical issue | 7 days |
| fix for a high issue | 30 days |
| fix for everything else | 90 days |

The agent auto-updates over a signed release channel, so a fix reaches hosts within
minutes of publishing. That means the targets above are bounded by how carefully we verify
a fix, not by how long delivery takes.

## Safe harbour

Good-faith research on this agent is welcome and will not be met with legal action,
provided you do not harm other people's data or service. Test against your own
installation or against the source. Do not test against other customers' hosts or our
production systems.

## Scope

This repository is the host agent. Findings in the hosted backend, the console or the
public collectors also go to the same address; say which component you mean.

Things that are true by design rather than bugs, and which we would rather discuss than
receive as findings:

- The service runs privileged on Linux. It has to, for eBPF and for reading other
  processes' stacks. We say so plainly in our trust documentation.
- A TLS-inspecting proxy in the path breaks the connection. The certificate pin is doing
  its job.
- `exec` is limited to an allow-list of binaries and never uses a shell, so "the agent runs
  commands" is expected; a way to run something outside that allow-list is not.

## Verifying a release

Every release asset and the release manifest are signed with our publisher key, and builds
are reproducible. If a binary's hash does not match the manifest, or the manifest signature
does not verify, treat that as a security issue and tell us.
