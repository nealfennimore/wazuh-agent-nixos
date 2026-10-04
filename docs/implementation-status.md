# Configuration coverage: status and remaining work

This document records which agent configuration sections the NixOS module
covers, and which work remains. The reference list is the "Configuration
sections" table in the upstream documentation. Sections that upstream marks
`manager` only are out of scope. This repository packages the agent alone.

The package is Wazuh 4.14.7. The generated `ossec.conf` comes from
`nixos/wazuh-agent/generate-agent-config.nix`. That file edits the template
`modules/wazuh/etc/ossec-agent.conf` at build time and appends an `<sca>`
block. `services.wazuh-agent.extraConfig` appends free-form XML, so every
section below is reachable today. "Missing" means that the section has no
first-class option and no entry in the generated file.

## Status summary

| Section | Status |
|---------|--------|
| `client` | Implemented |
| `client_buffer` | Implemented |
| `active-response` | Implemented |
| `sca` | Implemented |
| `syscheck` | Partially implemented |
| `localfile` | Template default, adapted for journald |
| `rootcheck` | Template default |
| `wodle name="syscollector"` | Template default, plus a NixOS package collector |
| `labels` | Implemented |
| `logging` | Implemented |
| `agent-upgrade` | Missing |
| `anti_tampering` | Missing |
| `socket` | Missing |
| `wodle name="command"` | Missing |
| `wodle name="osquery"` | Missing |
| `fluent-forward` | Missing |
| `github` | Missing |
| `ms-graph` | Missing |
| `office365` | Missing |
| `wodle name="aws-s3"` | Blocked by assertion |
| `wodle name="azure-logs"` | Blocked by assertion |
| `wodle name="docker-listener"` | Blocked by assertion |
| `gcp-pubsub` | Blocked by assertion, with a naming defect |
| `gcp-bucket` | Missing, and not blocked |

## Implemented sections

### client

The template supplies the section. The module substitutes the manager
address and port from `services.wazuh-agent.manager`. When
`registration.agentName`, `registration.groups`, `registration.caFile`,
`registration.certFile` or `registration.keyFile` is set, the module adds
an `<enrollment>` block with the matching elements. The enrollment options
also drive the separate `wazuh-agent-auth` unit, through `-A`, `-G`, `-v`,
`-x` and `-k`. Two template values stay hardcoded: `config-profile` and
`crypto_method`.

### client_buffer

The `buffer.enable`, `buffer.queueSize` and `buffer.eventsPerSecond` options
fill the block. The option types carry the bounds that
`src/config/buffer-config.c` enforces, so a bad value fails at evaluation.

### active-response

`activeResponse.enable` controls the block and the `wazuh-execd` unit
together. The `activeResponse.capability.<name>.enable` options grant each
response only what it needs. The grant table is `responseRequirements` in
`nixos/wazuh-agent/default.nix`.

### sca

The template ships no `<sca>` block, so the module appends one. The
`sca.enable`, `sca.scanOnStart`, `sca.interval` and `sca.skipNfs` options
fill it. Policies load from `ruleset/sca` in the package.

### labels

The `labels` option renders an appended `<labels>` block, one
`<label key="...">` per entry, with an optional `hidden="yes"` attribute.
Keys and values are written verbatim, because the Wazuh parser does not
decode XML entities. Assertions reject empty keys, keys that start with
`_`, and the characters the parser cannot carry. No block is written when
the option is empty.

### logging

The `logging.plain` and `logging.json` options render an appended
`<logging>` block with the matching `log_format` value. The block is
always written, so the file states the choice instead of relying on the
silent fallback to plain. An assertion requires at least one format.

### syscheck (partial)

The `syscheck.directories` and `syscheck.ignore` options replace the FHS
directory list and extend the ignore list. All other elements keep the
template values: `frequency`, `scan_on_start`, `nodiff`, the skip flags,
`process_priority`, `max_eps` and `synchronization`.

## Template defaults

Three sections reach the final file unmodified or nearly so, with no option
behind them.

- `rootcheck` runs every 12 hours with the upstream file lists.
- `localfile` keeps the active-responses reader and the two command
  readers. The module replaces the three syslog file readers with one
  journald reader, because NixOS logs to journald.
- `wodle name="syscollector"` runs hourly with hardware, OS, network and
  package scans. The package scan finds nothing on a stock NixOS host, so
  patch 06 in `pkgs/patches` adds a collector that reads the system closure
  that the `wazuh-nix-inventory` unit writes. The README section
  "Vulnerability detection" describes it.

The template also ships a disabled `wodle name="open-scap"` block. Upstream
removed that module, so the block is dead configuration.

## Blocked sections

An assertion in `nixos/wazuh-agent/default.nix` rejects a configuration
that names `aws-s3`, `azure-logs`, `gcloud-pubsub` or `docker-listener`.
These wodles write a SQLite database beside their own code. The module
links `wodles` into the read-only Nix store, so the write fails at runtime.
The assertion turns that runtime failure into an evaluation failure.

The assertion has two defects. See the remaining work below.

## Remaining work

### Defects

1. The store-safety assertion checks the name `gcloud-pubsub`. Wazuh 4.x
   configures GCP as a top-level `<gcp-pubsub>` section, not as a wodle
   with that name. The check therefore never matches a real configuration.
2. `gcp-bucket` writes its state beside its code in the same way, and the
   assertion does not cover it.

### New options, in priority order

1. `wodle name="osquery"` — run osquery and collect its results. Needs an
   osquery package on the daemon PATH and a writable results path under
   `/var/ossec/var`.
2. `wodle name="command"` — run a scheduled command. Treat with care: the
   section selects a program, which is the same privilege boundary as the
   `<localfile>` command readers.
3. `agent-upgrade` — set `ca_verification` for remote upgrade. Low value
   here, because the package is immutable and upgrades go through
   `nixos-rebuild`. An option that disables remote upgrade outright is the
   better fit.
4. `socket` — define custom logcollector output sockets, with a
   `<localfile>` target attribute to match.
5. `fluent-forward`, `github`, `ms-graph`, `office365` — cloud and
   forwarding collectors. Verify the state-path behavior of each before
   work starts. A collector that writes beside its code needs the same
   treatment as the blocked wodles.

### Unblock work for the cloud wodles

The blocked wodles stay blocked until their state paths move under
`/var/ossec/var`. That needs either an upstream patch or a wrapper that
sets each wodle's database path. Fix the assertion defects first, so the
block is accurate while it stands.

### Out of scope

- `anti_tampering` protects against package removal on Windows agents.
  The Linux module has no use for it.
- `wodle name="agent-key-polling"` and every section that upstream marks
  `manager` only.
