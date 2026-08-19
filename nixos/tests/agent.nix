# A headless NixOS VM test. Run it with:
#
#   nix build .#checks.x86_64-linux.agent
#
# Scope: this test proves that the module evaluates, that activation succeeds,
# and that the generated ossec.conf is correct. It does not prove enrollment.
# Enrollment needs a running Wazuh manager, and this repository packages only
# the agent, so wazuh-agent-auth is expected to fail inside the test VM. For
# that reason the test does not assert that the daemons stay running.
{
  pkgs,
  wazuhModule,
}:
pkgs.testers.runNixOSTest {
  name = "wazuh-agent";

  nodes.agent = {
    imports = [wazuhModule];

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

    with subtest("the state directory belongs to the wazuh user"):
        agent.succeed("test -d /var/ossec/etc")
        agent.succeed("test $(stat -c %U /var/ossec) = wazuh")

    with subtest("every daemon has a unit and a wrapper"):
        for daemon in daemons:
            agent.succeed(f"systemctl cat {daemon}.service >/dev/null")
            agent.succeed(f"test -u /run/wrappers/bin/{daemon}")
  '';
}
