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

## Options

| Option | Default | Purpose |
|--------|---------|---------|
| `enable` | `false` | Runs the agent daemons. |
| `package` | this flake | The agent package. |
| `manager.host` | none | The address of the Wazuh manager. Required. |
| `manager.port` | `1514` | The agent traffic port on the manager. |
| `registration.host` | `null` | A separate enrollment server. `null` means the manager. |
| `registration.port` | `1515` | The enrollment port. |
| `agentAuthPasswordFile` | `null` | A file that holds the enrollment password. |
| `extraConfig` | `""` | XML appended to the generated `ossec.conf`. |
| `config` | `null` | The complete `ossec.conf`. Replaces the generated file. |
| `path` | see module | Packages on the PATH of the daemons. |

Do not put the enrollment password in the Nix store. The store is world
readable. Point `agentAuthPasswordFile` at a path outside the store.

`config` and `extraConfig` conflict. An assertion rejects both together.

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

## Known limits

- The build is not reproducible across Wazuh dependency versions. The
  `libbpf-bootstrap` CMake file ships in the dependency tarball, not in
  `wazuh/wazuh`, so it changes without a matching source tag. `prePatch` edits
  that file by structure and aborts the build if the structure changes.
- `security.wrappers` marks all five daemons `setuid` and `setgid`. The daemons
  already run as the `wazuh` user, so most of them do not need this.
- The derivation sets `dontFixup = true`.
- There is no NixOS VM test yet.
