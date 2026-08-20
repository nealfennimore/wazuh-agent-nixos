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

The agent enrolls once, then writes `/var/ossec/.agent-registered`. Delete that
file to force a new enrollment.

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
sudo rm -f /var/ossec/.agent-registered /var/ossec/etc/client.keys
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
| `agentAuthPasswordFile` | `null` | A file that holds the enrollment password. |
| `syscheck.directories` | `[ "/etc" "/boot" ]` | Directories that file integrity monitoring watches. |
| `syscheck.ignore` | the two systemd credential stores | Paths excluded from monitoring. |
| `extraConfig` | `""` | XML appended to the generated `ossec.conf`. |
| `config` | `null` | The complete `ossec.conf`. Replaces the generated file. |
| `path` | see module | Packages on the PATH of the daemons. |

Do not put the enrollment password in the Nix store. The store is world
readable. Point `agentAuthPasswordFile` at a path outside the store.

`config` and `extraConfig` conflict. An assertion rejects both together.

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

The test boots a VM, then confirms that activation succeeds and that the
generated `ossec.conf` is correct. It does not confirm enrollment. Enrollment
needs a running manager, and this repository packages only the agent.

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

Four options are left out on purpose. `ProtectProc`, `ProcSubset`,
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
- `SystemCallFilter`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies` and
  `PrivateDevices` are not set. Each one is plausible and none is tested. The
  agent forks python wodles, loads an eBPF object in syscheckd, and reads
  netlink from syscollector.
