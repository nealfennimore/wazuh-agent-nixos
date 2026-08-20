# A headless NixOS VM test. Run it with:
#
#   nix build .#checks.x86_64-linux.agent
#
# Scope: this test proves that the module evaluates, that activation succeeds,
# that the generated ossec.conf is correct, and that the four daemons which do
# not need a manager stay running under the sandbox. It does not prove
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

  nodes.agent = {
    imports = [ wazuhModule ];

    services.wazuh-agent = {
      enable = true;
      manager.host = "192.0.2.10";
      manager.port = 1514;
    };
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
  '';
}
