# A headless NixOS VM test. Run it with:
#
#   nix build .#checks.x86_64-linux.agent
#
# Scope: this test proves that the module evaluates, that activation succeeds,
# that the generated ossec.conf is correct, that the four daemons which do not
# need a manager stay running under the sandbox, that logcollector reads entries
# out of the journal, and that every command reader resolves on the daemon PATH.
#
# It does not prove delivery to a manager, and it does not prove
# enrollment. Enrollment needs a running Wazuh manager, and this repository
# packages only the agent, so wazuh-agent-auth is expected to fail inside the
# test VM, and wazuh-agentd is excluded from the start-up check for the same
# reason.
{
  pkgs,
  wazuhModule,
}:
pkgs.testers.runNixOSTest {
  name = "wazuh-agent";

  nodes.agent =
    { pkgs, ... }:
    {
      imports = [ wazuhModule ];

      services.wazuh-agent = {
        enable = true;
        manager.host = "192.0.2.10";
        manager.port = 1514;
      };

      # The journald subtest reads a counter out of the logcollector state
      # file, which is JSON.
      environment.systemPackages = [ pkgs.jq ];
    };

  testScript = ''
    daemons = [
        "wazuh-agentd",
        "wazuh-logcollector",
        "wazuh-syscheckd",
        "wazuh-modulesd",
        "wazuh-execd",
    ]

    agent.wait_for_unit("multi-user.target")

    # setup-pre-wazuh builds the state directory and writes the configuration.
    # It is a oneshot without RemainAfterExit, so it reports inactive once it
    # finishes. Wait for its product rather than for its unit state.
    agent.wait_for_file("/var/ossec/etc/ossec.conf", timeout=120)

    with subtest("the generated configuration names the manager"):
        agent.succeed("grep -q '<address>192.0.2.10</address>' /var/ossec/etc/ossec.conf")
        agent.succeed("grep -q '<port>1514</port>' /var/ossec/etc/ossec.conf")

    with subtest("the journald swap replaced the file readers exactly once"):
        agent.succeed(
            "test $(grep -c '<log_format>journald</log_format>' /var/ossec/etc/ossec.conf) -eq 1"
        )
        # The active response reader must survive as a plain file reader.
        agent.succeed(
            "grep -q '<location>/var/ossec/logs/active-responses.log</location>'"
            " /var/ossec/etc/ossec.conf"
        )
        # NixOS creates none of these, so none of them must remain.
        agent.fail("grep -q '<location>/var/log/syslog</location>' /var/ossec/etc/ossec.conf")
        agent.fail("grep -q '<location>/var/log/messages</location>' /var/ossec/etc/ossec.conf")
        agent.fail("grep -q '<location>/var/log/auth.log</location>' /var/ossec/etc/ossec.conf")

    with subtest("syscheck watches only directories that exist on NixOS"):
        agent.succeed("grep -q '<directories>/etc,/boot</directories>' /var/ossec/etc/ossec.conf")
        # /sbin and /usr/sbin do not exist here, and /bin and /usr/bin hold one
        # symlink each, so none of the four may survive.
        agent.fail(
            "grep -qE '<directories>[^<]*/(usr/)?s?bin' /var/ossec/etc/ossec.conf"
        )
        # Confirm the premise rather than trusting it.
        agent.fail("test -e /sbin")
        agent.fail("test -e /usr/sbin")

    with subtest("the systemd credential stores are ignored"):
        agent.succeed("grep -q '<ignore>/etc/credstore</ignore>' /var/ossec/etc/ossec.conf")
        agent.succeed(
            "grep -q '<ignore>/etc/credstore.encrypted</ignore>' /var/ossec/etc/ossec.conf"
        )
        # The upstream ignore that anchors the substitution must stay.
        agent.succeed("grep -q '<ignore>/sys/kernel/debug</ignore>' /var/ossec/etc/ossec.conf")

    with subtest("the package ships the definitions modulesd requires"):
        agent.succeed(
            "grep -q '^wazuh_modules.rlimit_nofile=' /var/ossec/etc/internal_options.conf"
        )

    with subtest("an upgrade refreshes package files and keeps host state"):
        # Recreate the state an upgrade leaves behind: an internal_options.conf
        # from a version before the key existed. wazuh_modules.rlimit_nofile
        # arrived in 4.13.0, and wazuh-modulesd exits 1 with
        # "(2301): Definition not found for:" when it is missing.
        agent.succeed(
            "grep -v '^wazuh_modules.rlimit_nofile=' /var/ossec/etc/internal_options.conf"
            " > /tmp/stale"
        )
        agent.succeed("cp /tmp/stale /var/ossec/etc/internal_options.conf")
        agent.fail(
            "grep -q '^wazuh_modules.rlimit_nofile=' /var/ossec/etc/internal_options.conf"
        )

        # Mark the files the host owns. These must survive.
        agent.succeed("echo marker-keys >> /var/ossec/etc/client.keys")
        agent.succeed("echo marker-local >> /var/ossec/etc/local_internal_options.conf")

        agent.succeed("systemctl start setup-pre-wazuh.service")

        agent.succeed(
            "grep -q '^wazuh_modules.rlimit_nofile=' /var/ossec/etc/internal_options.conf"
        )
        agent.succeed("grep -q marker-keys /var/ossec/etc/client.keys")
        agent.succeed("grep -q marker-local /var/ossec/etc/local_internal_options.conf")

    with subtest("the state directory belongs to the wazuh user"):
        agent.succeed("test -d /var/ossec/etc")
        agent.succeed("test $(stat -c %U /var/ossec) = wazuh")

    with subtest("no daemon is reachable through a setuid wrapper"):
        for daemon in daemons:
            agent.succeed(f"systemctl cat {daemon}.service >/dev/null")
            # The wrapper was mode -r-s--s--x owned wazuh:wazuh, so any local
            # user could execute the daemon as the account that owns
            # etc/client.keys.
            agent.fail(f"test -e /run/wrappers/bin/{daemon}")
            agent.succeed(
                f"systemctl show -p ExecStart --value {daemon}.service | grep -q /nix/store/"
            )
            agent.fail(
                f"systemctl show -p ExecStart --value {daemon}.service | grep -q /run/wrappers/"
            )

    with subtest("the sandbox is applied"):
        for daemon in daemons:
            for prop, want in [("NoNewPrivileges", "yes"), ("ProtectSystem", "strict")]:
                got = agent.succeed(
                    f"systemctl show -p {prop} --value {daemon}.service"
                ).strip()
                assert got == want, f"{daemon}: {prop} is {got!r}, wanted {want!r}"
            # Nothing calls setgroups any more, so no capability is needed.
            agent.succeed(
                f'test -z "$(systemctl show -p CapabilityBoundingSet --value {daemon}.service)"'
            )

    with subtest("the daemons still start under the sandbox"):
        # These four reach "Started (pid: N)" without a manager. agentd is
        # excluded: it needs a key, and enrollment cannot succeed in a VM that
        # has no manager to enroll against.
        unmanaged = [
            "wazuh-logcollector",
            "wazuh-syscheckd",
            "wazuh-modulesd",
            "wazuh-execd",
        ]
        for daemon in unmanaged:
            agent.succeed(f"systemctl restart {daemon}.service")
        # Type=exec reports active as soon as the binary is exec'd, so a daemon
        # that dies during start-up would pass an immediate check.
        agent.sleep(5)
        for daemon in unmanaged:
            agent.succeed(f"systemctl is-active {daemon}.service")

    with subtest("configuration assessment is configured and has policies"):
        # The shipped ossec-agent.conf has no sca block. install.sh writes one
        # into a different file, so this module never ran before.
        agent.succeed("test $(grep -c '<sca>' /var/ossec/etc/ossec.conf) -eq 1")

        # wmodules-sca.c loads every policy in ruleset/sca when none is named,
        # and preStart never copied that directory before.
        agent.succeed("test -d /var/ossec/ruleset/sca")
        agent.succeed("ls /var/ossec/ruleset/sca/*.yml >/dev/null")

        # This is what modulesd logs when the directory is missing.
        agent.fail(
            "journalctl -u wazuh-modulesd"
            " | grep -q 'Could not open the default SCA ruleset folder'"
        )

    with subtest("journald records reach the logcollector queue"):
        # ossec.conf naming journald proves configuration, not collection. The
        # reader dlopens libsystemd.so.0 by soname (journal_log.c:222), which
        # resolves only through the rpath that pkgs/wazuh-agent.nix adds, and
        # then opens the journal under ProtectSystem=strict with no
        # capabilities. Both can fail while the unit stays active.

        # read_journald.c:108 prints this after w_journal_context_create and
        # the initial seek both succeed. Nothing earlier in the file does.
        agent.wait_until_succeeds(
            "journalctl -u wazuh-logcollector"
            " | grep -q '(9203): Monitoring journal entries'",
            timeout=120,
        )

        # The three errors that disable the reader for the life of the
        # process. Each one leaves the unit active, so is-active misses them.
        #   1608 failed to connect to the journal
        #   1609 failed to seek to the end
        #   1610 failed to read the next entry
        for code in ["(1608)", "(1609)", "(1610)"]:
            agent.fail(f"journalctl -u wazuh-logcollector | grep -q '{code}'")

        # only-future-events defaults to true, so the probe must be written
        # after the reader opened the journal.
        for i in range(5):
            agent.succeed(
                "systemd-cat --identifier=wazuh-journald-probe"
                f" echo wazuh-journald-ingest-probe-{i}"
            )

        # read_journald.c:173 hands each entry to w_msg_hash_queues_push under
        # the location "journald", and that function counts the entry
        # (logcollector.c:1836) before it reaches the socket. So this counts
        # entries read, not entries delivered, which is the only claim this VM
        # can support: it has no manager.
        #
        # logcollector.state_interval is 60, so the file is rewritten once a
        # minute and the first write lands a minute after the daemon starts.
        state = "/var/ossec/var/run/wazuh-logcollector.state"

        # Sum into a list and default to 0, so that jq prints a number even
        # before the journald record exists. Reading .events directly prints
        # nothing at that point, and `test "" -gt 0` is an error rather than a
        # retry, which buries the real wait in log noise.
        events = (
            """jq '[.global.files[] | select(.location == "journald")"""
            """ | .events] | add // 0' """
            + state
        )
        agent.wait_until_succeeds(
            f'test -f {state} && test "$({events})" -gt 0', timeout=240
        )

        # A target that accepts nothing would still count reads above. drops
        # is the queue rejecting them.
        drops = (
            """jq '[.global.files[] | select(.location == "journald")"""
            """ | .targets[].drops] | add // 0' """
            + state
        )
        agent.succeed(f'test "$({drops})" -eq 0')

    with subtest("every command reader resolves on the daemon PATH"):
        # ossec-agent.conf ships three command readers: df -P, a netstat
        # pipeline, and last -n 5. None of them names an absolute path, so each
        # one depends on services.wazuh-agent.path.
        #
        # A missing binary is silent. read_command.c:28 calls popen, which runs
        # /bin/sh -c and fails only when fork or pipe fails. A command that does
        # not exist makes the shell exit 127, popen still succeeds, and the
        # reader collects an empty result. So "Unable to execute command" at
        # read_command.c:30 never appears, and the only symptom is a counter
        # that never moves.
        #
        # Resolve each command against the PATH systemd gives the daemon.
        env = agent.succeed(
            "systemctl show -p Environment --value wazuh-logcollector.service"
        ).strip()
        daemon_path = None
        for entry in env.split():
            if entry.startswith("PATH="):
                daemon_path = entry[len("PATH="):]
        assert daemon_path, f"wazuh-logcollector has no PATH: {env!r}"

        # services.wazuh-agent.path goes through lib.makeBinPath, which appends
        # /bin to every entry. An entry that already ends in /bin lands as
        # .../bin/bin, a directory that does not exist, and the entry it was
        # meant to add is silently missing.
        entries = daemon_path.split(":")
        doubled = [p for p in entries if p.endswith("/bin/bin")]
        assert not doubled, f"path entries end in /bin/bin: {doubled}"
        assert "/run/current-system/sw/bin" in entries, daemon_path

        readers = agent.succeed(
            r"sed -n 's|.*<command>\(.*\)</command>.*|\1|p' /var/ossec/etc/ossec.conf"
        )
        binaries = set()
        for reader in readers.splitlines():
            # Each stage of a pipeline needs its own binary. netstat -tan is
            # piped through grep twice and then sort.
            for stage in reader.split("|"):
                words = stage.split()
                if words:
                    binaries.add(words[0])
        assert binaries, "the generated ossec.conf has no command reader"

        # /bin/sh by absolute path, because that is what popen execs. The
        # daemon PATH has no shell on it and does not need one.
        for binary in sorted(binaries):
            agent.succeed(
                f"env -i PATH={daemon_path} /bin/sh -c 'command -v {binary}'"
                " >/dev/null"
            )

    with subtest("the wazuh user can read the login records"):
        # last -n 5 reads /var/log/wtmp. systemd creates the file from its own
        # tmpfiles.d/var.conf as 0664 root:utmp, and nixpkgs builds systemd with
        # the utmp meson option on glibc, so systemd-update-utmp writes a record
        # at every boot.
        #
        # The wazuh user is not in the utmp group. Reading works only through
        # the world-read bit, so a host that tightens wtmp to 0660 silences this
        # reader with no error anywhere.
        agent.succeed("test -f /var/log/wtmp")
        agent.succeed("runuser -u wazuh -- test -r /var/log/wtmp")
  '';
}
