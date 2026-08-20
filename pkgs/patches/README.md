# Downstream Wazuh patches

These patches target Wazuh 4.14.7. Each file has one reason to exist so a
future version bump can test and retire it independently.

| Patch | Why it exists | Removal condition |
|---|---|---|
| `00-do-not-strip-read-only-library-copies.patch` | `cp` preserves the Nix store libraries' non-writable mode. Modern binutils `strip` copies back with `O_TRUNC` rather than renaming over the target, so stripping the mode-0555 copy fails. The patch removes only these two strip commands; a global `STRIP_TOOL=true` would leak into vendored sub-makes. | Upstream makes the copies writable before stripping, or binutils can again replace a non-writable target using only directory permissions. |
| `01-link-libdb-for-agent.patch` | Upstream defines and builds `DB_LIB` but adds it to no Linux agent link line. Berkeley DB is a suspected librpm/rpmdb dependency, but that consumer has not been proven without a counterfactual build. | Upstream links `DB_LIB` for `TARGET=agent`, or the agent builds and its libdb-dependent paths run without it. |
| `02-build-openssl-with-perl.patch` | The vendored OpenSSL `config` launcher has an FHS `#!/usr/bin/env perl` shebang. Calling `Configure` through the packaged Perl interpreter avoids it; the former rewrite to a bare `env` could not produce a valid shebang. | The vendored launcher runs in the sandbox, or upstream invokes `Configure` through an explicit interpreter. |
| `03-use-wazuh-home.patch` | Store-path executables make upstream derive the immutable package tree as the runtime home. NixOS keeps mutable agent state in `/var/ossec`, supplied through `WAZUH_HOME`. | Upstream gives the environment/configured home precedence over `/proc/self/exe`. |
| `04-systemd-owns-privilege-drop.patch` | systemd starts each process with the identity selected by the module. For ordinary daemons Wazuh's later `setgroups` fails without `CAP_SETGID`. For `wazuh-execd`, the optional `disable-account` response deliberately selects root; Wazuh's internal `setuid(wazuh)` would undo that explicit service setting. | Upstream can skip its privilege drop when systemd already selected the intended identity. |

The split also removed a derivation-time rewrite of
`src/external/openssl/config`. Patch 02 bypasses that launcher and calls
`Configure` through Perl, so editing the unused file had no effect.
