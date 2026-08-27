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
let
  storeProbe = pkgs.writeShellScript "store-probe" "exit 0";
in
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
        agentAuthPasswordFile = "/run/secrets/wazuh-authd-pass";
      };

      # Match the default ownership and mode used by sops-nix and agenix.
      # setup-pre-wazuh runs as wazuh, so opening this path directly must fail;
      # PID 1 has to provide it through LoadCredential instead.
      systemd.tmpfiles.rules = [
        "f /run/secrets/wazuh-authd-pass 0400 root root - test-enrollment-password"
      ];

      # The journald subtest reads a counter out of the logcollector state
      # file, which is JSON.
      environment.systemPackages = [ pkgs.jq ];
    };

  # The same module with the opt-in settings on, so one run covers both sides
  # of each. This node asserts configuration, capabilities and command lines.
  # Firing a response needs a manager to send one, and proving that
  # certificate verification works needs a manager holding a matching
  # certificate, which is checks.enrollment's ground rather than this one.
  nodes.responder =
    { pkgs, ... }:
    {
      imports = [ wazuhModule ];

      services.wazuh-agent = {
        enable = true;
        manager.host = "192.0.2.10";
        manager.port = 1514;
        activeResponse.enable = true;
        # host-deny is off by default. Turn it on here so the run covers the
        # one response that needs a path rather than a capability.
        activeResponse.capability.host-deny.enable = true;

        # Contents do not matter here. Nothing reads them without a manager,
        # and what this node checks is that the paths reach both enrollment
        # paths. A real key does not belong in the store.
        registration.caFile = pkgs.writeText "test-root-ca.pem" "";
        registration.certFile = pkgs.writeText "test-agent.pem" "";
        registration.keyFile = pkgs.writeText "test-agent-key.pem" "";
      };
    };

  # Active response on, but only the response that needs no capability. This
  # is the claim the per-response grant makes: turn the network ones off and
  # no unit in the module holds a capability, while execd still runs.
  nodes.notifier =
    { ... }:
    {
      imports = [ wazuhModule ];

      services.wazuh-agent = {
        enable = true;
        manager.host = "192.0.2.10";
        activeResponse.enable = true;
        activeResponse.capability = {
          firewall-drop.enable = false;
          route-null.enable = false;
          wazuh-slack.enable = true;
        };

        # Non-default values, so the buffer subtest proves the
        # substitution rather than the template.
        buffer.queueSize = 20000;
        buffer.eventsPerSecond = 250;

        # Non-default labels and log format, so the subtests prove the
        # appended sections rather than the defaults. The ampersand is
        # there on purpose: unescaped it would make OS_ReadXML reject the
        # file in every daemon at once.
        labels = {
          environment = "production";
          rack = {
            value = "row 4";
            hidden = true;
          };
          carrier = "AT&T";
        };
        logging.json = true;
      };
    };

  # The one response that cannot be reached without root. This node exists to
  # prove the escalation is asked for rather than assumed, and that it stays
  # inside the one unit that needs it.
  nodes.disabler =
    { ... }:
    {
      imports = [ wazuhModule ];

      services.wazuh-agent = {
        enable = true;
        manager.host = "192.0.2.10";
        activeResponse.enable = true;
        activeResponse.capability.disable-account.enable = true;
        buffer.enable = false;
      };
    };

  testScript = ''
    # wazuh-execd is not here. Active response is off by default, and execd
    # with active response disabled logs "Active response disabled" and
    # returns 0 (src/os_execd/execd.c:574-577), so the module defines no unit
    # for it. The subtest at the end covers both settings.
    daemons = [
        "wazuh-agentd",
        "wazuh-logcollector",
        "wazuh-syscheckd",
        "wazuh-modulesd",
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

    with subtest("activation relinks package files and keeps host state"):
        # Package configuration is a store link, so it cannot become the stale
        # mutable copy that earlier releases carried across upgrades.
        target = agent.succeed(
            "readlink /var/ossec/etc/internal_options.conf"
        ).strip()
        assert target.startswith("/nix/store/"), target
        agent.succeed(
            "grep -q '^wazuh_modules.rlimit_nofile='"
            " /var/ossec/etc/internal_options.conf"
        )

        # Mark the files the host owns. These must survive another activation.
        agent.succeed("echo marker-keys >> /var/ossec/etc/client.keys")
        agent.succeed("echo marker-local >> /var/ossec/etc/local_internal_options.conf")

        agent.succeed("systemctl start setup-pre-wazuh.service")

        target = agent.succeed(
            "readlink /var/ossec/etc/internal_options.conf"
        ).strip()
        assert target.startswith("/nix/store/"), target
        agent.succeed("grep -q marker-keys /var/ossec/etc/client.keys")
        agent.succeed("grep -q marker-local /var/ossec/etc/local_internal_options.conf")

    with subtest("the state layout is root-owned"):
        agent.succeed("test -d /var/ossec/etc")
        agent.succeed("test $(stat -c %U:%G /var/ossec) = root:wazuh")

    with subtest("package resources are links into the Nix store"):
        for tree in ["bin", "lib", "wodles", "agentless"]:
            target = agent.succeed(f"readlink /var/ossec/{tree}").strip()
            assert target.startswith("/nix/store/"), f"{tree}: target is {target!r}"
        target = agent.succeed("readlink /var/ossec/etc/ossec.conf").strip()
        assert target.startswith("/nix/store/"), f"ossec.conf: target is {target!r}"
        target = agent.succeed(
            "readlink /var/ossec/queue/syscollector/norm_config.json"
        ).strip()
        assert target.startswith("/nix/store/"), f"norm_config: target is {target!r}"
        agent.succeed("test $(stat -c %U:%G /var/ossec/etc) = root:wazuh")
        agent.succeed("test $(stat -c %a /var/ossec/etc) = 1770")
        agent.succeed(
            "test $(stat -c %U:%G /var/ossec/active-response/bin) = root:wazuh"
        )
        agent.succeed("test $(stat -c %a /var/ossec/active-response/bin) = 1770")
        for response in ["firewall-drop", "route-null", "host-deny"]:
            target = agent.succeed(
                f"readlink /var/ossec/active-response/bin/{response}"
            ).strip()
            assert target.startswith("/nix/store/"), (
                f"{response}: target is {target!r}"
            )
        agent.fail(
            "runuser -u wazuh -- rm /var/ossec/active-response/bin/firewall-drop"
        )
        agent.fail("runuser -u wazuh -- rm /var/ossec/etc/ossec.conf")
        agent.fail("test -e /var/ossec/active-response/bin/restart-wazuh")
        agent.fail("test -e /var/ossec/active-response/bin/restart.sh")

    with subtest("a root-only enrollment password is delivered as a credential"):
        agent.succeed("test $(stat -c %U:%G /run/secrets/wazuh-authd-pass) = root:root")
        agent.succeed("test $(stat -c %a /run/secrets/wazuh-authd-pass) = 400")
        agent.fail("runuser -u wazuh -- cat /run/secrets/wazuh-authd-pass")
        agent.succeed("grep -qx test-enrollment-password /var/ossec/etc/authd.pass")
        agent.succeed("test $(stat -c %U:%G /var/ossec/etc/authd.pass) = wazuh:wazuh")
        agent.succeed("test $(stat -c %a /var/ossec/etc/authd.pass) = 640")

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
        ]
        for daemon in unmanaged:
            agent.succeed(f"systemctl restart {daemon}.service")
        # Type=exec reports active as soon as the binary is exec'd, so a daemon
        # that dies during start-up would pass an immediate check.
        agent.sleep(5)
        for daemon in unmanaged:
            agent.succeed(f"systemctl is-active {daemon}.service")

    with subtest("the package code is read-only inside the units"):
        # The read-only guarantee rests on ProtectSystem = "strict": the
        # package trees have no mounts of their own, and the root of the
        # namespace is read-only. Only the state directories get a writable
        # bind. The sharedWritableDirs note in the module explains the
        # direction: the kernel detaches a mount whose mountpoint directory
        # is deleted, the setup refresh used to delete the package
        # directories, and a lost read-only mount fails open.
        #
        # These four are the state every daemon keeps.
        writable = [
            "/var/ossec/logs",
            "/var/ossec/queue",
            "/var/ossec/var",
            "/var/ossec/tmp",
        ]

        # etc and active-response are per unit, because both decide what the
        # agent runs. etc carries ossec.conf and shared/ar.conf;
        # active-response carries the response programs. Only the units that
        # write them get the write, so a compromise of one daemon does not
        # reach what another daemon runs.
        etc_writers = ["wazuh-agentd", "wazuh-agent-auth"]
        for daemon in daemons:
            rwp = agent.succeed(
                f"systemctl show -p ReadWritePaths --value {daemon}.service"
            )
            # systemd preserves the '-', '+', and '!' path modifiers in the
            # rendered property. Assertions below care about the effective
            # paths, not whether a missing path is ignored or how it is
            # namespace-resolved.
            rwp_paths = {path.lstrip("-+!") for path in rwp.split()}
            for path in writable:
                assert path in rwp_paths, f"{daemon}: {path} is not writable: {rwp!r}"
            if daemon in etc_writers:
                assert (
                    "/var/ossec/etc" in rwp_paths
                ), f"{daemon}: etc is read-only: {rwp!r}"
            else:
                assert (
                    "/var/ossec/etc" not in rwp_paths
                ), f"{daemon}: etc is writable and it does not write it: {rwp!r}"
            # No unit on this node runs responses. Active response is off
            # here, so wazuh-execd does not exist.
            assert (
                "/var/ossec/active-response" not in rwp_paths
            ), f"{daemon}: active-response is writable outside execd: {rwp!r}"
            ro = agent.succeed(
                f"systemctl show -p ReadOnlyPaths --value {daemon}.service"
            ).strip()
            assert ro == "", f"{daemon}: unexpected ReadOnlyPaths {ro!r}"

        # agent-auth is not in daemons, and it is the other unit that writes
        # etc. Assert it from the same table rather than trusting the split.
        rwp = agent.succeed(
            "systemctl show -p ReadWritePaths --value wazuh-agent-auth.service"
        )
        rwp_paths = {path.lstrip("-+!") for path in rwp.split()}
        assert (
            "/var/ossec/etc" in rwp_paths
        ), f"agent-auth cannot write client.keys: {rwp!r}"
        assert (
            "/var/ossec/var" in rwp_paths
        ), f"agent-auth cannot write the enrollment marker: {rwp!r}"

        # The mount table of the daemon's namespace, read from the host
        # through /proc/<pid>/mountinfo. Field five is the mount point and
        # field six holds the per-mount flags. The daemon must not share
        # the host namespace, the root must be read-only, every writable
        # state directory must be a mount that is writable and noexec, and
        # no mount that makes a package tree writable is tolerated.
        pid = agent.succeed(
            "systemctl show -p MainPID --value wazuh-logcollector.service"
        ).strip()
        host_ns = agent.succeed("readlink /proc/1/ns/mnt").strip()
        unit_ns = agent.succeed(f"readlink /proc/{pid}/ns/mnt").strip()
        assert host_ns != unit_ns, "logcollector shares the host mount namespace"

        mountinfo = agent.succeed(f"cat /proc/{pid}/mountinfo")
        agent.log("logcollector namespace mounts under /var/ossec:")
        for line in mountinfo.splitlines():
            if "/var/ossec" in line:
                agent.log(f"  {line}")

        def mount_state(path):
            """The (root, options) of the top mount at path, or None."""
            found = [
                (f[3], f[5])
                for f in (l.split() for l in mountinfo.splitlines())
                if len(f) > 5 and f[4] == path
            ]
            return found[-1] if found else None

        root_state = mount_state("/")
        assert root_state and root_state[1].split(",")[0] == "ro", (
            f"the namespace root is not read-only: {root_state}"
        )
        for path in writable:
            state = mount_state(path)
            assert state, f"{path} is not a mount in the namespace"
            flags = state[1].split(",")
            assert flags[0] == "rw", f"{path} mounted {state[1]}"
            assert "noexec" in flags, f"{path} lacks noexec: {state[1]}"
        # logcollector writes neither etc nor active-response, so neither
        # may carry a writable mount here, on top of the package trees.
        for tree in [
            "bin",
            "lib",
            "ruleset",
            "wodles",
            "agentless",
            "etc",
            "active-response",
        ]:
            state = mount_state(f"/var/ossec/{tree}")
            assert state is None or state[1].split(",")[0] == "ro", (
                f"/var/ossec/{tree} is writable through a mount: {state}"
            )

        # The write itself. Enter the namespace as root: the package trees
        # must refuse the write and the state directories must still take
        # one. A read-only mount refuses root too, so a pass here proves
        # the mount rather than a permission bit.
        #
        # -r and -w are load-bearing. setns() alone keeps the caller's root
        # directory, so an absolute path keeps resolving through the host
        # namespace, where /var/ossec/bin is writable, and the probe tests
        # nothing. With no argument the two flags take the root and working
        # directory of the target process.
        agent.fail(f"nsenter -t {pid} -m -r -w -- touch /var/ossec/bin/probe")
        agent.fail("test -e /var/ossec/bin/probe")
        agent.succeed(f"nsenter -t {pid} -m -r -w -- touch /var/ossec/logs/probe")
        agent.succeed(f"nsenter -t {pid} -m -r -w -- rm /var/ossec/logs/probe")

        # The two files that decide what the agent runs. A <localfile> with
        # <log_format>command</log_format> in ossec.conf makes logcollector
        # run any command, and shared/ar.conf maps a response name to a
        # binary. logcollector must not be able to write either, and it must
        # not be able to stage a response binary.
        agent.fail(
            f"nsenter -t {pid} -m -r -w -- sh -c 'echo x >> /var/ossec/etc/ossec.conf'"
        )
        agent.fail(
            f"nsenter -t {pid} -m -r -w -- touch /var/ossec/etc/shared/ar.conf"
        )
        agent.fail(
            f"nsenter -t {pid} -m -r -w -- touch /var/ossec/active-response/bin/probe"
        )
        agent.fail("test -e /var/ossec/active-response/bin/probe")
        # The file is still readable. Every daemon reads its configuration.
        agent.succeed(f"nsenter -t {pid} -m -r -w -- head -1 /var/ossec/etc/ossec.conf")

    with subtest("writable state does not execute, read-only code does"):
        # NoExecPaths must match the unit's writable set, so writable and
        # executable never overlap and no needless mount is created under
        # the state directory. Every mount there is one more thing the
        # refresh can detach. The same rule includes syscheckd's single
        # writable audit-rules file for consistency.
        for daemon in daemons:
            rwp = agent.succeed(
                f"systemctl show -p ReadWritePaths --value {daemon}.service"
            )
            nep = agent.succeed(
                f"systemctl show -p NoExecPaths --value {daemon}.service"
            )
            under_state = set(
                p for p in nep.split() if p.startswith("/var/ossec/")
            )
            wanted = set(p for p in rwp.split() if p.startswith("/var/ossec/"))
            assert under_state == wanted, (
                f"{daemon}: NoExecPaths {sorted(under_state)} does not match"
                f" the writable set {sorted(wanted)}"
            )
            # Store links need no exec carve-out in any daemon.
            ep = agent.succeed(
                f"systemctl show -p ExecPaths --value {daemon}.service"
            ).strip()
            assert ep == "", f"{daemon}: ExecPaths is {ep!r}"

        # A staged payload must run outside the namespace and refuse inside
        # it, so the refusal is the noexec mount rather than the file. The
        # package copy of wazuh-control must keep running inside the
        # namespace: the read-only trees stay executable, which is what the
        # response binaries need to map their libraries.
        agent.succeed(
            "printf '#!/bin/sh\\nexit 0\\n' > /var/ossec/logs/probe.sh"
            " && chmod 755 /var/ossec/logs/probe.sh"
        )
        agent.succeed("/var/ossec/logs/probe.sh")
        agent.fail(f"nsenter -t {pid} -m -r -w -- /var/ossec/logs/probe.sh")
        agent.succeed("rm /var/ossec/logs/probe.sh")
        agent.succeed(
            f"nsenter -t {pid} -m -r -w -- /var/ossec/bin/wazuh-control info -t"
        )

    with subtest("syscheckd loses IP traffic and nothing else does"):
        # The rootcheck probe binds and closes without one packet
        # (src/rootcheck/check_rc_ports.c:60-92), and the manager path runs
        # through agentd over a Unix socket, so syscheckd works with no IP
        # traffic at all. The other daemons keep their traffic: agentd
        # talks to the manager, and a host configuration can point reader
        # commands and wodles at the network. No unit carries
        # SocketBindDeny: OS_Connect binds every client socket to an
        # ephemeral port before it connects (src/os_net/os_net.c), so a
        # bind deny cuts the agent off from its manager. The
        # deliberately-absent note in the module holds the full story.
        deny = agent.succeed(
            "systemctl show -p IPAddressDeny --value wazuh-syscheckd.service"
        ).strip()
        assert deny != "", "syscheckd has no IPAddressDeny"
        for daemon in ["wazuh-agentd", "wazuh-logcollector", "wazuh-modulesd"]:
            deny = agent.succeed(
                f"systemctl show -p IPAddressDeny --value {daemon}.service"
            ).strip()
            assert deny == "", f"{daemon}: IPAddressDeny is {deny!r}"

        # SocketBindDeny must stay absent everywhere; a regression here
        # breaks enrollment with "(1208): Unable to connect".
        for daemon in daemons + ["wazuh-agent-auth"]:
            deny = agent.succeed(
                f"systemctl show -p SocketBindDeny --value {daemon}.service"
            ).strip()
            assert deny == "", f"{daemon}: SocketBindDeny is {deny!r}"

    with subtest("the setup unit runs without a network"):
        got = agent.succeed(
            "systemctl show -p PrivateNetwork --value setup-pre-wazuh.service"
        ).strip()
        assert got == "yes", f"setup-pre-wazuh PrivateNetwork is {got!r}"

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

    with subtest("active response is off, and says so"):
        # The template ships it enabled. Four other modules use the same
        # <disabled> spelling, so check the count as well as the value.
        agent.succeed(
            "test $(grep -c '<active-response>' /var/ossec/etc/ossec.conf) -eq 1"
        )
        agent.succeed(
            "grep -A1 '<active-response>' /var/ossec/etc/ossec.conf"
            " | grep -q '<disabled>yes</disabled>'"
        )

        # No unit, because execd with active response disabled returns 0 at
        # start and would report inactive forever.
        agent.fail("systemctl cat wazuh-execd.service")

        # No unit holds a capability in this configuration.
        for daemon in daemons:
            got = agent.succeed(
                f"systemctl show -p AmbientCapabilities --value {daemon}.service"
            ).strip()
            assert got == "", f"{daemon} holds {got!r} with active response off"

    with subtest("active response on grants execd exactly what it needs"):
        responder.wait_for_file("/var/ossec/etc/ossec.conf", timeout=120)

        responder.succeed(
            "grep -A1 '<active-response>' /var/ossec/etc/ossec.conf"
            " | grep -q '<disabled>no</disabled>'"
        )

        # execd exists here, and it is the only unit with a capability.
        responder.succeed("systemctl cat wazuh-execd.service >/dev/null")
        for prop in ["CapabilityBoundingSet", "AmbientCapabilities"]:
            got = responder.succeed(
                f"systemctl show -p {prop} --value wazuh-execd.service"
            ).strip()
            assert got == "cap_net_admin", f"execd {prop} is {got!r}"

        # Only execd. The grant must not leak to the other four.
        for daemon in daemons:
            got = responder.succeed(
                f"systemctl show -p AmbientCapabilities --value {daemon}.service"
            ).strip()
            assert got == "", f"{daemon} holds {got!r}, only execd should"

        # Every active response resolves its binary through get_binary_path,
        # which is a PATH lookup, and a miss goes to active-responses.log
        # rather than the journal. These are the three that can work under
        # this sandbox, so all three binaries must resolve.
        env = responder.succeed(
            "systemctl show -p Environment --value wazuh-execd.service"
        ).strip()
        execd_path = None
        for entry in env.split():
            if entry.startswith("PATH="):
                execd_path = entry[len("PATH="):]
        assert execd_path, f"wazuh-execd has no PATH: {env!r}"
        for binary in ["iptables", "ip6tables", "route", "curl"]:
            responder.succeed(
                f"env -i PATH={execd_path} /bin/sh -c 'command -v {binary}'"
                " >/dev/null"
            )

        # host-deny appends to a hardcoded /etc/hosts.deny. ProtectSystem =
        # "strict" makes /etc read-only and the file is normally root owned,
        # so selecting that response has to fix both. Neither is a capability.
        rwp = responder.succeed(
            "systemctl show -p ReadWritePaths --value wazuh-execd.service"
        )
        rwp_paths = {path.lstrip("-+!") for path in rwp.split()}
        assert "/etc/hosts.deny" in rwp_paths, f"execd cannot write hosts.deny: {rwp}"
        for path in ["logs", "queue", "var", "tmp", "active-response"]:
            assert f"/var/ossec/{path}" in rwp_paths, (
                f"execd lost /var/ossec/{path}: {rwp}"
            )
        responder.succeed("test $(stat -c %U /etc/hosts.deny) = wazuh")
        responder.succeed("runuser -u wazuh -- test -w /etc/hosts.deny")

        # execd is the unit that runs manager-supplied commands, so the
        # read-only code trees matter most here. Those trees hold no mount
        # of their own: the strict root keeps them read-only, so the unit
        # must carry no ReadOnlyPaths at all, and its writable set must be
        # the state directories, with active-response among them for the
        # lock directories that firewall-drop and host-deny keep inside
        # active-response/bin.
        ro = responder.succeed(
            "systemctl show -p ReadOnlyPaths --value wazuh-execd.service"
        ).strip()
        assert ro == "", f"execd: unexpected ReadOnlyPaths {ro!r}"
        assert (
            "/var/ossec/active-response" in rwp_paths
        ), f"execd: active-response is not writable, the response locks break: {rwp!r}"

        # Store-linked responses resolve to executable inodes on the store
        # mount. The sticky runtime directory needs no executable carve-out.
        ep = responder.succeed(
            "systemctl show -p ExecPaths --value wazuh-execd.service"
        ).strip()
        assert ep == "", f"execd carries a writable exec carve-out: {ep!r}"

        # execd runs whatever the manager selects through ar.conf, and
        # restart-wazuh and restart.sh would start daemons outside systemd.
        # They are absent from the package, so no child noexec mount on the
        # replaceable /var/ossec/bin store link is needed.
        nep = responder.succeed(
            "systemctl show -p NoExecPaths --value wazuh-execd.service"
        )
        assert "/var/ossec/bin" not in nep, f"needless mount on store link: {nep!r}"
        assert (
            "/var/ossec/etc" not in nep
        ), f"execd holds a needless mount on etc: {nep!r}"

        # Not enabled on the default node, so nothing there was widened.
        agent.fail("test -e /etc/hosts.deny")

    with subtest("store-linked responses execute and staged files do not"):
        # active-response is writable and noexec. A regular payload staged
        # there must fail, while a link that resolves onto the Nix store mount
        # must execute. This is what removes the writable-executable overlap.
        responder.wait_for_unit("wazuh-execd.service")
        pid = responder.succeed(
            "systemctl show -p MainPID --value wazuh-execd.service"
        ).strip()
        assert pid not in ("", "0"), f"wazuh-execd is not running: {pid!r}"

        def execd_carve_out():
            """The mount options at active-response/bin in execd, or None."""
            mountinfo = responder.succeed(f"cat /proc/{pid}/mountinfo")
            for line in mountinfo.splitlines():
                f = line.split()
                if len(f) > 5 and f[4] == "/var/ossec/active-response/bin":
                    return f[5]
            return None

        # A probe rather than a real response. Real responses read a message
        # from stdin and act on the host.
        probe = "/var/ossec/active-response/bin/probe.sh"

        def staged_exec_is_denied():
            responder.succeed(
                f"printf '#!/bin/sh\\nexit 0\\n' > {probe} && chmod 755 {probe}"
            )
            got = responder.succeed(
                f"nsenter -t {pid} -m -r -w -- sh -c '{probe}; echo $?'"
            ).strip()
            responder.succeed(f"rm -f {probe}")
            # 126 is the shell's code for a file it found and could not
            # execute, which is what a noexec mount produces.
            return got == "126"

        before = execd_carve_out()
        assert before is None, f"execd still has an exec carve-out: {before}"
        assert staged_exec_is_denied(), "execd ran a staged response payload"
        responder.succeed(
            "ln -s ${storeProbe}"
            " /var/ossec/active-response/bin/store-probe"
        )
        responder.succeed(
            f"nsenter -t {pid} -m -r -w --"
            " /var/ossec/active-response/bin/store-probe"
        )

        responder.succeed("systemctl start setup-pre-wazuh.service")

        after = execd_carve_out()
        assert after is None, f"the refresh created an exec carve-out: {after}"
        assert staged_exec_is_denied(), "execd ran a staged payload after refresh"

        # execd did not restart, so the namespace under test is the one the
        # refresh ran against rather than a fresh one.
        still = responder.succeed(
            "systemctl show -p MainPID --value wazuh-execd.service"
        ).strip()
        assert still == pid, f"execd restarted during the refresh: {pid} -> {still}"
        responder.fail(
            "test -e /var/ossec/active-response/bin/store-probe"
        )

        # The refresh still clears the directory's contents. A lock
        # directory left behind by a killed response reads as held, because
        # the responses use mkdir on it as their mutex.
        responder.succeed("mkdir -p /var/ossec/active-response/bin/fw-drop")
        responder.succeed("systemctl start setup-pre-wazuh.service")
        responder.fail("test -e /var/ossec/active-response/bin/fw-drop")

        # And the response programs are back after it.
        responder.succeed("test -x /var/ossec/active-response/bin/firewall-drop")

        # The two unsupported restart responses are absent rather than
        # relying on a child noexec mount over a store-link inode.
        responder.fail("test -e /var/ossec/active-response/bin/restart-wazuh")
        responder.fail("test -e /var/ossec/active-response/bin/restart.sh")

    with subtest("only execd reaches the response programs"):
        # The reach this narrows. execd runs the response programs with
        # CAP_NET_ADMIN, or as root under disable-account. While
        # active-response was writable in every daemon, a compromise of any
        # one of them staged a binary that execd later ran. This node has
        # active response on, so it is the case that matters.
        for daemon in daemons:
            rwp = responder.succeed(
                f"systemctl show -p ReadWritePaths --value {daemon}.service"
            )
            rwp_paths = {path.lstrip("-+!") for path in rwp.split()}
            assert (
                "/var/ossec/active-response" not in rwp_paths
            ), f"{daemon} can stage a response binary: {rwp!r}"
            if daemon != "wazuh-agentd":
                assert (
                    "/var/ossec/etc" not in rwp_paths
                ), f"{daemon} can rewrite ossec.conf or ar.conf: {rwp!r}"

        # Enforcement, in the namespace of a daemon that is not execd.
        other = responder.succeed(
            "systemctl show -p MainPID --value wazuh-logcollector.service"
        ).strip()
        responder.fail(
            f"nsenter -t {other} -m -r -w --"
            " touch /var/ossec/active-response/bin/staged"
        )
        responder.fail("test -e /var/ossec/active-response/bin/staged")
        responder.fail(
            f"nsenter -t {other} -m -r -w --"
            " sh -c 'echo x >> /var/ossec/etc/shared/ar.conf'"
        )
        # It still reads them, which is all it ever needed.
        responder.succeed(
            f"nsenter -t {other} -m -r -w -- head -1 /var/ossec/etc/ossec.conf"
        )
        responder.succeed(
            f"nsenter -t {other} -m -r -w --"
            " test -x /var/ossec/active-response/bin/firewall-drop"
        )

    with subtest("a response that needs no capability grants none"):
        # execd still runs, because active response is on. It holds nothing,
        # because the only response enabled is the one that needs a binary
        # and not a privilege. This is what makes the grant subtractive
        # rather than all-or-nothing.
        notifier.wait_for_file("/var/ossec/etc/ossec.conf", timeout=120)
        notifier.succeed("systemctl cat wazuh-execd.service >/dev/null")

        for prop in ["CapabilityBoundingSet", "AmbientCapabilities"]:
            got = notifier.succeed(
                f"systemctl show -p {prop} --value wazuh-execd.service"
            ).strip()
            assert got == "", f"execd holds {got!r} with only wazuh-slack on"

        # And it did not lose what it does need.
        env = notifier.succeed(
            "systemctl show -p Environment --value wazuh-execd.service"
        ).strip()
        notifier_path = None
        for entry in env.split():
            if entry.startswith("PATH="):
                notifier_path = entry[len("PATH="):]
        assert notifier_path, f"wazuh-execd has no PATH: {env!r}"
        notifier.succeed(
            f"env -i PATH={notifier_path} /bin/sh -c 'command -v curl' >/dev/null"
        )
        notifier.fail("test -e /etc/hosts.deny")

    with subtest("only disable-account escalates, and only execd"):
        disabler.wait_for_file("/var/ossec/etc/ossec.conf", timeout=120)

        # shadow reads the real UID, so this response is unreachable without
        # it. Nothing else in the module runs as root.
        got = disabler.succeed(
            "systemctl show -p User --value wazuh-execd.service"
        ).strip()
        assert got == "root", f"execd runs as {got!r}, disable-account needs root"

        for daemon in daemons:
            got = disabler.succeed(
                f"systemctl show -p User --value {daemon}.service"
            ).strip()
            assert got == "wazuh", f"{daemon} runs as {got!r}, only execd may be root"

        # The group must stay wazuh. execd and the scripts it forks write
        # active-responses.log, and UMask 0027 under root:root would leave a
        # file wazuh-logcollector cannot read, which is how the manager learns
        # a response ran at all.
        got = disabler.succeed(
            "systemctl show -p Group --value wazuh-execd.service"
        ).strip()
        assert got == "wazuh", f"execd group is {got!r}, logcollector needs wazuh"

        # passwd rewrites shadow through a temporary file and a lock in the
        # same directory, so the whole of /etc has to be writable.
        rwp = disabler.succeed(
            "systemctl show -p ReadWritePaths --value wazuh-execd.service"
        )
        rwp_paths = {path.lstrip("-+!") for path in rwp.split()}
        assert "/etc" in rwp_paths, f"execd cannot write /etc: {rwp}"
        for path in ["logs", "queue", "var", "tmp", "active-response"]:
            assert f"/var/ossec/{path}" in rwp_paths, (
                f"execd lost /var/ossec/{path}: {rwp}"
            )

        # And the escalation must not appear where it was not asked for.
        for node, name in [(agent, "agent"), (responder, "responder"), (notifier, "notifier")]:
            node.fail("systemctl show -p User --value wazuh-execd.service | grep -qx root")

    with subtest("the agent event buffer is configurable"):
        # The generated replacement drops the template's comment line, so
        # <disabled> sits directly under <client_buffer> on every node and
        # grep -A1 reads the value this module chose.
        conf = "/var/ossec/etc/ossec.conf"

        # The default node carries the upstream defaults.
        agent.succeed(f"test $(grep -c '<client_buffer>' {conf}) -eq 1")
        agent.succeed(f"grep -q '<queue_size>5000</queue_size>' {conf}")
        agent.succeed(f"grep -q '<events_per_second>500</events_per_second>' {conf}")
        agent.succeed(
            f"grep -A1 '<client_buffer>' {conf} | grep -q '<disabled>no</disabled>'"
        )

        # Non-default values reach the file, so the substitution is proven
        # rather than the template. wazuh-agentd rejects a queue_size over
        # 100000 at start, and the option type carries the same bounds, so
        # these values are also ones the daemon accepts.
        notifier.succeed(f"grep -q '<queue_size>20000</queue_size>' {conf}")
        notifier.succeed(f"grep -q '<events_per_second>250</events_per_second>' {conf}")

        # Turning the buffer off writes yes into the one block that means
        # the buffer, not into one of the four other <disabled> elements.
        disabler.succeed(f"test $(grep -c '<client_buffer>' {conf}) -eq 1")
        disabler.succeed(
            f"grep -A1 '<client_buffer>' {conf} | grep -q '<disabled>yes</disabled>'"
        )

    with subtest("the agent log format is configurable"):
        # The template ships no <logging> block, so the appended one is
        # the only one. That count matters: os_logging_config reads the
        # first log_format in the file, so a second block would win
        # silently over the options.
        agent.succeed(f"test $(grep -c '<logging>' {conf}) -eq 1")
        agent.succeed(f"grep -q '<log_format>plain</log_format>' {conf}")
        notifier.succeed(f"grep -q '<log_format>plain,json</log_format>' {conf}")

        # Every daemon parses the section on its own (shared/debug_op.c),
        # and an unknown value is fatal, so a live daemon proves the parse.
        # The JSON stream is a second file beside the plain one, written
        # by the same _log_function call, so any daemon log line lands in
        # both once json is on.
        notifier.wait_for_file("/var/ossec/logs/ossec.json", timeout=120)
        notifier.succeed("grep -q '\"timestamp\"' /var/ossec/logs/ossec.json")
        notifier.succeed("test -s /var/ossec/logs/ossec.log")

        # Plain-only means no JSON file at all. debug_op.c opens
        # LOGJSONFILE only when the json flag is set, so an existing file
        # here would mean the default node parsed a json format.
        agent.succeed("test -s /var/ossec/logs/ossec.log")
        agent.fail("test -e /var/ossec/logs/ossec.json")

    with subtest("labels reach the generated configuration"):
        # No labels configured, no section at all. An empty <labels>
        # block would read as configured.
        agent.fail(f"grep -q '<labels>' {conf}")

        notifier.succeed(f"test $(grep -c '<labels>' {conf}) -eq 1")
        notifier.succeed(
            f"grep -q '<label key=\"environment\">production</label>' {conf}"
        )
        # hidden renders as an attribute, and only where it was asked for.
        notifier.succeed(
            f"grep -q '<label key=\"rack\" hidden=\"yes\">row 4</label>' {conf}"
        )
        notifier.fail(f"grep -q 'key=\"environment\" hidden' {conf}")
        # The ampersand must arrive escaped. Unescaped it fails XML
        # parsing in every daemon, not only the labels reader.
        notifier.succeed(
            f"grep -q '<label key=\"carrier\">AT&amp;T</label>' {conf}"
        )
        notifier.fail(f"grep -q '<label key=\"carrier\">AT&T</label>' {conf}")

        # wazuh-agentd is the daemon that reads <labels>
        # (src/client-agent/config.c:68), and ClientConf runs before
        # enrollment (client-agent/main.c:203). A label error is fatal
        # there, so an enrollment attempt proves the section parsed.
        # Enrollment itself cannot succeed in a VM with no manager.
        notifier.wait_until_succeeds(
            "journalctl -u wazuh-agentd | grep -q 'Requesting a key from server'",
            timeout=120,
        )

        # The daemons that do not need a manager must still be running
        # with labels and json logging in the file.
        for daemon in ["wazuh-logcollector", "wazuh-syscheckd", "wazuh-modulesd"]:
            notifier.succeed(f"systemctl is-active {daemon}.service")

    with subtest("enrollment is unverified unless a CA is configured"):
        # Off by default, and the absence must be an absent block rather than
        # an empty one, which would read as configured.
        agent.fail("grep -q '<enrollment>' /var/ossec/etc/ossec.conf")
        execstart = agent.succeed(
            "systemctl show -p ExecStart --value wazuh-agent-auth.service"
        )
        for flag in [" -v ", " -x ", " -k "]:
            assert flag not in execstart, f"agent-auth has {flag!r}: {execstart}"

    with subtest("a configured CA reaches both enrollment paths"):
        # There are two. agent-auth runs once, and wazuh-agentd enrolls itself
        # on every boot from the <enrollment> block. Configuring one and not
        # the other leaves the path that runs more often unverified.
        conf = responder.succeed("cat /var/ossec/etc/ossec.conf")
        assert "<enrollment>" in conf, "no enrollment block on the responder"
        for element in [
            "server_ca_path",
            "agent_certificate_path",
            "agent_key_path",
        ]:
            assert f"<{element}>" in conf, f"{element} missing from ossec.conf"

        execstart = responder.succeed(
            "systemctl show -p ExecStart --value wazuh-agent-auth.service"
        )
        for flag in ["-v", "-x", "-k"]:
            assert f" {flag} " in execstart, f"agent-auth lacks {flag}: {execstart}"

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
