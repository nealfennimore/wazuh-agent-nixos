# wazuh-agent

A Nix flake that packages the Wazuh agent and runs it on NixOS.

The flake targets Wazuh 4.14.7 with external dependency set `DEPS_VERSION=54`.
It supports `x86_64-linux` and `aarch64-linux`.

## Contents

| Output | Purpose |
|--------|---------|
| `packages.wazuh-agent` | The agent build. `wazuh-control` is the main program. |
| `nixosModules.wazuh-agent` | The `services.wazuh-agent` NixOS module. |
| `overlays.default` | Adds `wazuh-agent` to a package set. |
| `devShells.default` | A shell for work on this repository. |

The NixOS module supplies its own package. The overlay is optional.

## Add the agent to a NixOS host

1. Add the flake as an input.

   ```nix
   inputs.wazuh-agent.url = "git+https://github.com/nealfennimore/wazuh-agent-nixos";
   ```

2. Import the module and set the manager address.

   ```nix
   {
     imports = [inputs.wazuh-agent.nixosModules.wazuh-agent];

     services.wazuh-agent = {
       enable = true;
       manager.host = "192.168.1.2";
     };
   }
   ```

3. Rebuild the host.

   ```bash
   sudo nixos-rebuild switch
   ```

The agent enrolls once, then writes `/var/ossec/var/.agent-registered`. Delete
that file to force a new enrollment. Older versions wrote
`/var/ossec/.agent-registered`, and an existing marker there still counts.

`examples/` holds a complete flake and a commented host configuration.

## Verify the service

1. Confirm that the five daemons are active.

   ```bash
   systemctl status wazuh.target wazuh-agentd wazuh-logcollector \
     wazuh-syscheckd wazuh-modulesd wazuh-execd
   ```

2. Read the enrollment result.

   ```bash
   journalctl -u wazuh-agent-auth -b
   ```

3. Confirm that the generated configuration reached the state directory.

   ```bash
   grep -A2 '<server>' /var/ossec/etc/ossec.conf
   ```

4. Read the agent log.

   ```bash
   tail -n 50 /var/ossec/logs/ossec.log
   ```

The manager must list the agent as `Active`. Run `agent_control -l` on the
manager to confirm this.

## Enrollment fails

Enrollment uses two different ports. `agent-auth` talks to `authd` on the
registration port, 1515 by default. The daemons then send agent data to
`remoted` on the manager port, 1514 by default.

A wrong enrollment port gives this error:

```
agent-auth: ERROR: SSL error (1). Connection refused by the manager.
SSL routines::unexpected eof while reading
```

That message means that the manager accepted the connection and then closed
it. Confirm that `authd` runs, and that `services.wazuh-agent.registration.port`
matches the port that `authd` listens on.

To enroll again after a failure, delete the marker file and restart the unit.

```bash
sudo rm -f /var/ossec/var/.agent-registered /var/ossec/.agent-registered \
  /var/ossec/etc/client.keys
sudo systemctl restart wazuh-agent-auth
sudo systemctl restart wazuh.target
```

## Options

| Option | Default | Purpose |
|--------|---------|---------|
| `enable` | `false` | Runs the agent daemons. |
| `package` | this flake | The agent package. |
| `manager.host` | none | The address of the Wazuh manager. Required. |
| `manager.port` | `1514` | The agent traffic port on the manager. |
| `registration.host` | `null` | A separate enrollment server. `null` means the manager. |
| `registration.port` | `1515` | The enrollment port. Used even when `registration.host` is `null`. |
| `registration.caFile` | `null` | CA that the manager is verified against. `null` means no verification. |
| `registration.certFile` | `null` | Client certificate this agent presents. Needs `keyFile` and `caFile`. |
| `registration.keyFile` | `null` | Private key for `certFile`. Keep it outside the store. |
| `agentAuthPasswordFile` | `null` | A file that holds the enrollment password. |
| `syscheck.directories` | `[ "/etc" "/boot" ]` | Directories that file integrity monitoring watches. |
| `syscheck.ignore` | the two systemd credential stores | Paths excluded from monitoring. |
| `sca.enable` | `true` | Runs Security Configuration Assessment scans. |
| `sca.scanOnStart` | `true` | Scans when the agent starts. |
| `sca.interval` | `"12h"` | Time between scans. |
| `sca.skipNfs` | `true` | Skips NFS mounts during a scan. |
| `activeResponse.enable` | `false` | Lets the agent act on a finding, not only report it. |
| `activeResponse.capability.<name>.enable` | see below | Whether that response is provisioned. |
| `extraConfig` | `""` | XML appended to the generated `ossec.conf`. |
| `config` | `null` | The complete `ossec.conf`. Replaces the generated file. |
| `path` | see module | Packages on the PATH of the daemons. |

Do not put the enrollment password in the Nix store. The store is world
readable. Point `agentAuthPasswordFile` at a path outside the store. Root-only
sources created by sops-nix, agenix, or another secret manager are supported;
systemd reads the source and delivers it to the setup service as a credential.

`config` and `extraConfig` conflict. An assertion rejects both together.

### Configuration assessment

The `ossec-agent.conf` that ships in the package has no `<sca>` block.
Upstream writes that block into the `ossec.conf` that `install.sh` generates,
from `etc/templates/config/generic/sca.template`. This module builds from
`ossec-agent.conf` instead, so Security Configuration Assessment never ran.
This module appends the block itself.

SCA replaces the deprecated rootcheck `system_audit` check. That deprecation
is the warning `wazuh-syscheckd` logs on every start:

```
WARNING: The check_unixaudit option is deprecated in favor of the SCA module.
```

Keep the `<system_audit>` entries. The manager pushes those policy files into
`etc/shared`, and rootcheck reads them. The warning names a replacement, not a
fault.

Policies come from the package at `ruleset/sca`. Upstream installs the set
that matches the distribution and falls back to
`sca_distro_independent_linux.yml`, which is what NixOS gets. `preStart`
copies that directory into `/var/ossec`.

### Active response

Active response is off by default. That is what the sandbox already enforced
before the option existed: the template ships active response enabled, but
`wazuh-execd` runs as the `wazuh` user with no capabilities, and the response
that matters, `firewall-drop`, execs `iptables` to add `INPUT` and `FORWARD`
`DROP` rules. So the agent detected and could not respond, and nothing said
so.

With the option off, `ossec.conf` carries `<disabled>yes</disabled>` and no
`wazuh-execd` unit is defined. `execd` with active response disabled logs
`Active response disabled` and returns 0, so a unit for it would report
inactive forever.

```nix
services.wazuh-agent.activeResponse.enable = true;
```

Each response is granted what it needs, and nothing more.

```nix
services.wazuh-agent.activeResponse = {
  enable = true;
  capability.host-deny.enable = true;
  capability.route-null.enable = false;
};
```

| Response | Needs | Default |
|----------|-------|---------|
| `firewall-drop` | `iptables` and `ip6tables`, `CAP_NET_ADMIN` | on |
| `route-null` | `route` from `nettools`, `CAP_NET_ADMIN` | on |
| `wazuh-slack` | `curl`, no capability | on |
| `host-deny` | `/etc/hosts.deny` writable by the `wazuh` user | off |
| `firewalld-drop` | `firewall-cmd`, and a polkit rule | follows `services.firewalld.enable` |
| `disable-account` | `wazuh-execd` running as **root** | off |

`host-deny` is off by default because the grant is a different shape. The path
is hardcoded, `ProtectSystem = "strict"` makes `/etc` read-only, and the file
is normally owned by root. Enabling it adds `/etc/hosts.deny` to
`ReadWritePaths` for `wazuh-execd` alone and creates the file owned by the
`wazuh` user. Little reads that file on a modern NixOS host, so enable it only
if something on yours does.

`firewalld-drop` follows `services.firewalld.enable`, so it needs no attention
when firewalld is on or off. The binary comes with the firewalld package
already. What it adds is a polkit rule letting the `wazuh` user call
`org.fedoraproject.FirewallD1.all`. That action id is every runtime change
firewalld accepts, because firewalld does not split runtime authorization more
finely. Permanent changes are a separate action and stay denied.

`disable-account` runs `wazuh-execd` as **root**, and no capability
substitutes. `shadow` reads the real UID (`passwd.c:71,767`), so neither a
capability nor a setuid wrapper reaches it. The module warns at evaluation when
this is on, because `wazuh-execd` is the unit that runs what the manager tells
it to run: a compromised or impersonated manager reaches root through it. Set
`registration.caFile` if you enable this. The group stays `wazuh` so that
`logs/active-responses.log` remains readable by `wazuh-logcollector`, which is
how the manager learns a response ran.

Apart from `disable-account`, `CAP_NET_ADMIN` is the only capability any unit
in this module holds, and only `wazuh-execd` holds it. Turn off
`firewall-drop` and `route-null` and no unit holds a capability at all.

**These options do not restrict the manager.** Every script the package ships
stays in `active-response/bin`, and the manager decides which to invoke. They
control whether the binary and the privilege that script needs are present. A
response the manager sends that is disabled here fails.

Each script resolves its binary with a `PATH` lookup, and a miss is written to
`logs/active-responses.log` rather than to the journal. `logcollector` reads
that file, so the manager sees it. The agent's own journal does not.

Four are not offered, and none of the four is a capability question.

| Script | Why not |
|--------|---------|
| `disable-account` | Runs `passwd -l`. `shadow` takes `amroot` from the **real** UID (`passwd.c:71,767`) and refuses the flag when it is not 0 (`passwd.c:972`). A setuid wrapper changes the effective UID, so it does not help. This needs `wazuh-execd` to run as root. |
| `firewalld-drop` | Needs `firewalld` running and reachable over D-Bus. A host decision, not a grant. |
| `restart-wazuh`, `restart.sh` | Restart through `wazuh-control`, which starts daemons outside the supervision systemd already provides. |
| `ipfw`, `npf`, `pf`, `kaspersky` | BSD firewalls, and a vendor CLI that is not packaged here. |

### Verify the manager during enrollment

Enrollment does not verify the manager unless a CA is configured. Without one
the client context keeps the OpenSSL default, `SSL_VERIFY_NONE`, so the
handshake completes against any certificate. The agent records this at
`mdebug1`, which does not print at the default log level.

```nix
services.wazuh-agent.registration.caFile = "/var/lib/wazuh-certs/root-ca.pem";
```

This covers both enrollment paths, which matters because there are two. The
`agent-auth` unit runs once and gets `-v`. `wazuh-agentd` enrolls itself from
the `<enrollment>` block on every boot and gets `server_ca_path`. Configuring
one and not the other leaves the path that runs more often unverified.

Verification checks the chain, then matches the subject alternative names, and
failing that the common name, against the address the agent connects to. So
the manager's certificate must name `manager.host`, or `registration.host`
when that is set. A manager using the certificate it generates for itself does
not pass. That is a manager-side change, not an agent one.

`registration.certFile` and `registration.keyFile` add a client certificate.
Set them together, and set `caFile` as well: a client certificate proves the
agent to the manager and does not make the agent check the manager. An
assertion rejects both mistakes. The manager verifies a client certificate
only when its own `ssl_agent_ca` is set.

Put the key outside the Nix store. Nothing copies these files, so their own
permissions are what matter, and the `wazuh` user must be able to read them.

### File integrity monitoring on NixOS

Upstream watches `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` and `/boot`.
NixOS has no `/sbin` and no `/usr/sbin`, and `/bin` and `/usr/bin` hold one
symlink each, `sh` and `env`. Four of those six entries monitor nothing, so the
default drops them.

Nothing is lost. Every binary on NixOS lives in `/nix/store` under a path that
is a hash of its own contents, which is a stronger guarantee than a periodic
checksum. Watch the mutable surface instead:

```nix
services.wazuh-agent.syscheck.directories = [
  "/etc"
  "/boot"
  "/root"
  "/home"
];
```

Do not add `/nix/store`. It is immutable and large enough to make a checksum
scan expensive for no gain. Add `/run/current-system/sw/bin` only if you want
every system rebuild reported as several hundred changes.

## Test in a QEMU VM

The flake builds a throwaway VM with the agent enabled. The VM configuration
is `examples/vm.nix`.

1. Build and start the VM.

   ```bash
   nix build .#vm
   ./result/bin/run-wazuh-agent-vm
   ```

2. Log in on the serial console. The user is `root` and the password is
   `wazuh`. The console also accepts `Ctrl-a x` to quit QEMU.

3. Check the units.

   ```bash
   systemctl status wazuh.target
   journalctl -u wazuh-agent-auth -b
   ```

`nixos-rebuild build-vm --flake .#wazuh-agent-vm` builds the same VM.

The VM sends agent traffic to `10.0.2.2`. That address is the host machine
under QEMU user mode networking. Run a Wazuh manager on the host, and the
agent reaches it with no extra network setup. The VM also forwards host port
2222 to its own SSH port.

The VM writes to a disk image named `wazuh-agent.qcow2` in the working
directory. Delete that file to start from a clean state. This matters after
enrollment, because the agent keeps its key in `/var/ossec`.

## Run the automated test

```bash
nix build .#checks.x86_64-linux.agent
```

The test boots a VM, then confirms that activation succeeds, that the generated
`ossec.conf` is correct, that logcollector reads the journal, and that every
command reader resolves on the daemon PATH. It needs no manager, so it stays
fast.

## Run the enrollment test

```bash
nix build .#checks.x86_64-linux.enrollment
```

This test boots two VMs. One runs the agent module. The other runs the Wazuh
manager container image from Docker Hub. It confirms that the agent enrolls
against `authd`, that the manager records the enrollment in its own
`client.keys`, that the agent connects to `remoted`, and that an event written
on the agent reaches the manager's archive.

Expect about six minutes. Most of that is the manager: the unit loads a
multi-gigabyte image, and the manager then initializes its databases before it
opens port 1515. The test starts the manager first and boots the agent only
after those ports are open, so the console stays quiet during the wait.

The manager image is not pinned in this repository, because a manifest digest
and a hash cannot be guessed. Write the pin first:

```bash
./nixos/tests/prefetch-manager-image.sh 4.14.7
git add nixos/tests/wazuh-manager-image.amd64.json
```

The script writes `nixos/tests/wazuh-manager-image.<arch>.json`.
`nixos/tests/wazuh-manager-image.nix` reads that file and passes it to
`dockerTools.pullImage`, so no hash is edited by hand. Until the file exists,
this check throws with the same instructions. `checks.agent` is not affected.

Commit the file before you run the check. A flake copies only the files that
git tracks, so an uncommitted pin is invisible to Nix.

One run produces one architecture. Pass a second argument to pin the other:

```bash
./nixos/tests/prefetch-manager-image.sh 4.14.7 arm64
```

Keep the manager version in step with `version` in `pkgs/wazuh-agent.nix`.
Wazuh supports an agent older than its manager. It does not support an agent
newer than its manager.

The test runs the manager alone. It does not run the indexer or the dashboard.
The check reads the manager's archive file and never reads an index, the two
extra images are much larger than the manager image, and the indexer needs a
TLS certificate set that this repository does not hold.

## Run the upstream integration suites

```bash
nix build .#checks.x86_64-linux.integration
```

This check boots one VM and runs the upstream integration tests from
`modules/wazuh/tests/integration` with `pytest`. The test framework comes from
[wazuh/qa-integration-framework](https://github.com/wazuh/qa-integration-framework),
which `pkgs/wazuh-testing.nix` builds at the tag that matches the submodule.

The suite proves the built binaries, not the NixOS module. The suite stops the
module's systemd units, rewrites `ossec.conf` per test, and runs the daemons as
root through `wazuh-control`, the way upstream packages run them. The module
units and the sandbox are the ground of `checks.agent` and
`checks.enrollment`.

The default run covers every agent-side suite: `test_agentd`,
`test_enrollment`, `test_execd`, `test_fim`, `test_logcollector`, `test_sca`
and `test_syscollector`. Expect several hours. `test_fim` is most of that. To
narrow the selection, pass `suites` or `extraPytestFlags` where `flake.nix`
imports `nixos/tests/integration.nix`.

A short exclusion list applies to `test_fim`, and it lives in `suiteFlags` in
`nixos/tests/integration.nix` with a reason on each entry. The exclusions
fall in two classes. The whodata cases and the audit-rule tests need audit
infrastructure that NixOS cannot provide, such as the `audisp-af_unix`
plugin at `/sbin` and the `yum` or `apt` package managers. Three single
realtime cases lose a timing race inside a VM, and their scheduled
counterparts cover the same assertions.

The check writes two artifacts per suite into the output: `report-<suite>.xml`
in JUnit form and `log-<suite>.txt` with the full pytest output. The check
fails when any suite reports a failure.

Expect friction on the first runs. The suites assume an upstream package
installation, and three shims in `nixos/tests/integration.nix` bridge the
differences. That file documents each shim. A test that fails on an
environment assumption rather than on agent behavior belongs in
`extraPytestFlags` as a `--deselect` entry.

To confirm the framework package alone, build it first:

```bash
nix build .#wazuh-testing
```

If the build reports a hash mismatch for the source, copy the hash from the
error message into `pkgs/wazuh-testing.nix`.

## Build the package alone

```bash
nix build .#wazuh-agent
```

The build fetches 27 dependency tarballs from `packages.wazuh.com`. The build
host must reach that server.

## Move to a new Wazuh version

1. Move the `modules/wazuh` submodule to the new tag.
2. Read `DEPS_VERSION` in `src/Makefile` at that tag.
3. Read `HTTP_REQUEST_BRANCH` in the same file.
4. Regenerate the dependency hashes.

   ```bash
   cd pkgs/dependencies
   DEPS_VERSION=<new value> WAZUH_VERSION=<new tag> \
     HTTP_REQUEST_REV=<new commit> ./prefetch-external-dependencies.sh
   ```

5. Copy the three hashes that the script prints into `pkgs/wazuh-agent.nix`.
6. Set `version`, `dependencyVersion`, and `wazuhRev` in the same file.

The script rewrites `pkgs/dependencies/external_dependencies.nix`. It writes
nothing if any download fails.

## Hardening

The daemons run as the `wazuh` user under systemd. They start from the store
path directly. This module does not use `security.wrappers`.

An earlier version did. It built a setuid and setgid wrapper per daemon, at
mode `-r-s--s--x` owned `wazuh:wazuh`. The final `x` is the world execute bit,
so every local user could run those binaries as the account that owns
`/var/ossec` and therefore `etc/client.keys`. The wrappers served no purpose,
because systemd already sets `User` and `Group`, and because the `w_homedir`
patch makes the daemons read `WAZUH_HOME` from the environment.

Every unit drops all capabilities and runs with `NoNewPrivileges`,
`ProtectSystem = "strict"` and `ReadWritePaths = [ "/var/ossec" ]`, plus the
usual `Protect*` and `Restrict*` set.

`SystemCallFilter`, `RestrictAddressFamilies`, `MemoryDenyWriteExecute` and
`PrivateDevices` are applied. `checks.enrollment` is what tests them, because
each one breaks a scan rather than the daemon that runs it, and `systemctl
is-active` cannot see that. The check asserts that syscollector, SCA,
rootcheck and file integrity monitoring each reach their own end line, and
that no daemon died of a blocked syscall.

Inside every daemon unit, only the state directories are writable: `etc`,
`logs`, `queue`, `var`, `tmp` and `active-response`. Everything else under
`/var/ossec`, including the package trees `bin`, `lib`, `ruleset`, `wodles`
and `agentless`, stays read-only through the strict root. The setup unit owns
those copies as the `wazuh` user, so without this every daemon can rewrite
code that later runs. The path that matters is `wazuh-execd`: the active
response binaries load their libraries from `/var/ossec/lib` through their
`$ORIGIN/../../lib` rpath, and `restart-wazuh` execs `bin/wazuh-control`.
`active-response` stays writable, because `firewall-drop` and `host-deny`
create their lock directories inside `active-response/bin`. That is the
residual gap, and closing it needs root-owned package trees.

The direction of that list is deliberate. An earlier version kept `/var/ossec`
writable and stacked `ReadOnlyPaths` mounts over the package trees.
`checks.agent` caught those mounts vanishing, and the mechanism is the
kernel: deleting a mountpoint directory detaches the mounts every namespace
holds on it, and the setup unit deleted exactly those directories on every
activation during its refresh. A lost read-only mount fails open and says
nothing. A lost writable bind fails closed: the daemon cannot write its
state, and says so. The read-only guarantee therefore rests on the root
remount, the setup refresh replaces directory contents and keeps the
directory inodes, and the setup unit uses `ProtectSystem = "full"` with no
`/var/ossec` bind at all, so nothing it mounts can leak into a daemon
namespace through peer-group propagation.

`SocketBindDeny = "any"` is set on every unit except `wazuh-syscheckd`.
Nothing in an agent listens, so a bind is a compromised daemon that opens a
listener. rootcheck runs inside `wazuh-syscheckd` and detects an open port
when `bind()` fails on it, so the deny there reports every port on the host
as a finding.

The setup unit runs with `PrivateNetwork`. It copies files and reads a
credential that PID 1 already resolved, so it has no reason to see a network.

The writable state directories all carry `noexec`, so writable and executable
never overlap: a payload staged in `queue`, `logs` or `tmp` cannot run, and
the read-only trees stay executable, which the response binaries need for
their library mappings. The one exception is `wazuh-execd`, whose `ExecPaths`
carve-out keeps `active-response/bin` executable. That directory is both
writable and executable, and it is the residual gap named above.

`wazuh-syscheckd` carries `IPAddressDeny = "any"`, the inverse of its
`SocketBindDeny` exemption. The rootcheck probe binds and closes without one
packet, and the manager path runs through `wazuh-agentd` over a Unix socket,
so syscheckd keeps `bind()` and loses IP traffic. The other daemons keep
their traffic: a host configuration can point reader commands and wodles at
the network, and a deny there fails silently.

Four other options are left out on purpose. `ProtectProc`, `ProcSubset`,
`PrivateUsers` and `PrivatePIDs` each hide or remap other processes. rootcheck
finds a hidden process by comparison of `kill(pid, 0)` and `getsid(pid)`
against `/proc/<pid>`. Any of those four makes the two views disagree for every
process on the host, so rootcheck reports the whole process table as hidden
processes. The agent does not fail. It produces findings that are not real.

`ProtectHome` is `read-only` rather than `true`, because `true` replaces
`/root` and `/home` with empty directories, and syscheck logs no error when it
monitors an empty directory.

To relax any of this for one daemon, set the option again:

```nix
systemd.services.wazuh-syscheckd.serviceConfig.ProtectHome = false;
```

## Known limits

- The build is not reproducible across Wazuh dependency versions. The
  `libbpf-bootstrap` CMake file ships in the dependency tarball, not in
  `wazuh/wazuh`, so it changes without a matching source tag. `prePatch` edits
  that file by structure and aborts the build if the structure changes.
- The derivation sets `dontFixup = true`.
- File integrity monitoring runs in scheduled mode. `whodata` mode loads an
  eBPF object, and `bpf` is in `@privileged` rather than `@system-service`, so
  it needs a `SystemCallFilter` exception that this module does not add.
- `activeResponse.capability` offers six of the scripts the package ships.
  `restart-wazuh` and `restart.sh` are not among them: they restart through
  `wazuh-control`, which starts daemons outside the supervision systemd
  already provides. `ipfw`, `npf` and `pf` are BSD firewalls, and `kaspersky`
  needs a vendor CLI that is not packaged here.
- With active response enabled, a local compromise of the `wazuh` user
  reaches whatever `wazuh-execd` holds. execd reads commands from
  `queue/alerts/execq`, a socket the `wazuh` user owns, and the response
  list in `etc/shared/ar.conf` is a file the manager writes through the same
  user. This is upstream's architecture, and no mount in this module closes
  it. The read-only code trees raise the cost of that path. They do not
  remove it. Weigh this in the same place the `disable-account` warning
  points: what execd holds is what a compromise gains.
