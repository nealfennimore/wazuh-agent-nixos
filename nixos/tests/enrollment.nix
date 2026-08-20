# A two node NixOS test: the agent module against a real Wazuh manager.
#
#   nix build .#checks.x86_64-linux.enrollment
#
# Scope: this test proves what checks.agent cannot. It proves that the agent
# enrolls against authd, that the manager records the enrollment, that the
# agent connects to remoted, and that an event written on the agent reaches the
# manager's archive.
#
# It needs the manager container image, which comes from Docker Hub. The pin
# lives in nixos/tests/wazuh-manager-image.<arch>.json, written by
# nixos/tests/prefetch-manager-image.sh. checks.agent needs no manager and
# stays fast.
{
  pkgs,
  wazuhModule,
}:
pkgs.testers.runNixOSTest {
  name = "wazuh-agent-enrollment";

  nodes.manager = {
    imports = [ ./manager-node.nix ];
  };

  nodes.agent =
    { nodes, ... }:
    {
      imports = [ wazuhModule ];

      services.wazuh-agent = {
        enable = true;

        # The address, not the node name. runNixOSTest writes both an A and an
        # AAAA record for every node into /etc/hosts, and the agent resolved
        # "manager" to 2001:db8:1::2 and failed with
        # "(1208): Unable to connect to enrollment service".
        #
        # The manager listens on IPv4. Wazuh binds IPv6 only when the
        # configuration asks for it, and the image's does not.
        manager.host = nodes.manager.networking.primaryIPAddress;
        manager.port = 1514;
        registration.port = 1515;
      };
    };

  testScript = ''
    start_all()

    with subtest("the manager container starts and listens"):
        # The unit loads a multi-gigabyte image before it runs anything.
        manager.wait_for_unit("docker-wazuh-manager.service", timeout=900)

        # The image starts the daemons from cont-init.d/2-manager, which ends
        # in `wazuh-control start`. That runs after the container is up, so
        # the ports open later than the unit does.
        #   1515 authd, enrollment
        #   1514 remoted, agent traffic
        manager.wait_for_open_port(1515, timeout=900)
        manager.wait_for_open_port(1514, timeout=900)

    agent.wait_for_unit("multi-user.target")
    agent.wait_for_file("/var/ossec/etc/ossec.conf", timeout=120)

    with subtest("the agent enrolls against authd"):
        # The boot attempt fails, because the manager needs longer to start
        # than the agent does. That is the case the module already handles:
        # markRegistered writes no marker when client.keys is empty, so
        # ConditionPathExists does not skip the next attempt.
        agent.succeed("systemctl restart wazuh-agent-auth.service")
        agent.wait_for_file("/var/ossec/.agent-registered", timeout=180)
        agent.succeed("test -s /var/ossec/etc/client.keys")

        # The manager's own copy is the independent evidence. authd appends
        # the agent to its client.keys, under the node hostname.
        manager.wait_until_succeeds(
            "docker exec wazuh-manager"
            " grep -q ' agent ' /var/ossec/etc/client.keys",
            timeout=120,
        )

    with subtest("the agent connects to remoted"):
        # The daemons started before a key existed. Restart them by name:
        # restarting the target does not restart what the target wants.
        daemons = [
            "wazuh-agentd",
            "wazuh-logcollector",
            "wazuh-syscheckd",
            "wazuh-modulesd",
            "wazuh-execd",
        ]
        for daemon in daemons:
            agent.succeed(f"systemctl restart {daemon}.service")

        agent.wait_until_succeeds(
            "journalctl -u wazuh-agentd"
            " | grep -q '(4102): Connected to the server'",
            timeout=240,
        )

        # agentd rewrites this file continuously. last_ack moves only when the
        # manager answers, so it is manager-side evidence read from the agent.
        state = "/var/ossec/var/run/wazuh-agentd.state"
        agent.wait_until_succeeds(
            f"grep -q \"^status='connected'\" {state}", timeout=240
        )

    with subtest("an event written on the agent reaches the manager archive"):
        # logall_json archives every event that analysisd decodes, whether or
        # not a rule matches. The image ships it off, so an arbitrary probe
        # would be discarded and the check would prove nothing.
        #
        # Match the current value rather than assume it. The grep afterwards
        # is what fails if the element is not there at all.
        manager.succeed(
            "docker exec wazuh-manager sed -i -E"
            " 's|<logall_json>[^<]*</logall_json>|<logall_json>yes</logall_json>|'"
            " /var/ossec/etc/ossec.conf"
        )
        manager.succeed(
            "docker exec wazuh-manager"
            " grep -q '<logall_json>yes</logall_json>' /var/ossec/etc/ossec.conf"
        )

        # cont-init.d/2-manager runs `wazuh-control start` once, and s6
        # supervises only filebeat and a tail of ossec.log. So restarting the
        # daemons from inside the container fights no supervisor.
        #
        # Restart in the container, not the unit. The unit removes and
        # recreates the container, which would discard the edit above.
        manager.succeed(
            "docker exec wazuh-manager /var/ossec/bin/wazuh-control restart"
        )
        manager.wait_for_open_port(1514, timeout=300)

        # only-future-events defaults to true, so the probe must be written
        # after logcollector opened the journal. It was, several steps ago.
        token = "wazuh-enrollment-archive-probe"
        agent.succeed(f"systemd-cat --identifier=wazuh-probe echo {token}")

        # The agent buffers while remoted restarts, so this needs to retry.
        manager.wait_until_succeeds(
            f"docker exec wazuh-manager grep -q -F '{token}'"
            " /var/ossec/logs/archives/archives.json",
            timeout=300,
        )
  '';
}
