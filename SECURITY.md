# Security model

Jarvis is a **single-user, loopback-only** local tool. It is not a hardened
multi-tenant service and it must not be exposed to a LAN or the public internet
without adding authentication, TLS and a separate sandbox.

## Boundaries

- The HTTP server binds `127.0.0.1` and validates `Host`, `Origin` and
  `Sec-Fetch-Site`. Local processes are trusted; a local process can already
  read the user's files and start the Operator.
- `~/.jarvis-tools` is owner-only (0700). Session, memory and vector databases
  and their `-wal`/`-shm` sidecars are 0600. They contain private conversation
  and personal-memory data. A six-hour maintenance thread writes online SQLite
  backups under `backups/` (0600, five generations); prune databases and
  artifacts deliberately, and remember a backup is as sensitive as its source.
- Notes, web pages, tool output and model-generated code are untrusted data.
  Note text is wrapped in explicit `<<<UNTRUSTED …>>>` blocks before a model
  sees it.
- The Operator's **Safe** and **Standard** modes are approval layers, not an OS
  sandbox. In Standard, shell commands, file reads and browser navigation are
  generally available; destructive commands, credentials, uploads/downloads,
  HTTP writes and external-page JavaScript ask for approval. A prompt-injected
  page should still be treated as a possible attacker: the Operator is the
  most powerful component in the project.
- **Full** mode is explicit consent for autonomous operation on this machine.
  It removes most approvals. Do not select it for untrusted pages or notes.
- Generated skills and Auto-Heal patches run in a bubblewrap sandbox with a
  read-only project tree, disposable HOME, no network and resource limits when
  `bwrap` is available; SSH/GPG/cloud credentials, browser profiles, keyrings
  and provider auth files are hidden from the child. Generated tests run in the
  same sandbox before a patch is applied. This is defense in depth, not a VM.
  If `bwrap` is missing, the same code runs with the user's permissions.
- Memory extraction redacts credential-shaped strings before sending a turn to
  the provider and again before storing extracted facts. This is best-effort
  scrubbing, not a guarantee: keep secrets outside notes and chat.
- `web_research` pins DNS to a validated public address, rejects redirects to
  non-public hosts, disables environment proxies and uses one shared address
  classifier (`net_guard.py`) with the browser and Operator HTTP tools. The
  isolated crawler installs a route guard before navigation and discards a
  capture whose actual response peer is private (DNS rebinding); Scrapling
  redirects are validated hop-by-hop, and the evidence fallback fetches only
  public URLs with a matching hash. The Chromium lane also records the real
  response peer and refuses page content once a private peer is observed.
- Public lookups, Edge TTS and web research leave the machine. Local notes are
  not sent merely by opening the galaxy; asking a question sends retrieved
  evidence to the configured provider. Paid endpoints have local per-minute
  token buckets and an optional `JARVIS_DAILY_CALL_LIMIT` budget, so a prompt
  loop or runaway UI cannot spend without bound.
- The two remote viewer libraries are exact-version pinned with SHA-384
  integrity hashes and `crossorigin="anonymous"`; the browser refuses an
  altered response. The rest of the UI is served only from `viewer/`.

## Reporting

This is a local project; report issues to its owner. Do not publish a working
prompt-injection or credential-exfiltration chain against a live installation
without permission.
