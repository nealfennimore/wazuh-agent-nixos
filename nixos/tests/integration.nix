# Upstream integration tests, run inside a NixOS VM. Run it with:
#
#   nix build .#checks.x86_64-linux.integration
#
# Scope: this check runs the agent-side suites from
# modules/wazuh/tests/integration against the binaries this flake builds. The
# suite brings its own harness: it rewrites ossec.conf, starts and stops the
# daemons through wazuh-control, and replaces the manager with the
# RemotedSimulator and AuthdSimulator from wazuh/qa-integration-framework.
#
# The check therefore proves the binaries, not the NixOS module. The module
# only installs /var/ossec here. Its systemd units are stopped before pytest
# runs, because the suite must own the daemon lifecycle, and under the
# framework the daemons run as root, the way upstream packages run them.
# checks.agent and checks.enrollment are what prove the units, the sandbox
# and the enrollment flow.
#
# Three shims bridge the framework's assumptions to this installation:
#
#   - `service`         control_service() restarts the whole agent with
#                       `service wazuh-agent <action>`. NixOS has no
#                       service(8), so a shim maps it to wazuh-control.
#   - wazuh-control     The package build removed `cd $LOCAL` from the
#                       script, so it derives its directory from the caller's
#                       working directory. A wrapper pins that directory.
#   - WAZUH_HOME        Patch 03 makes the daemons read WAZUH_HOME and
#                       nothing else. The wrapper and the pytest environment
#                       both export it, so daemons start no matter which
#                       path the framework uses.
{
  pkgs,
  wazuhModule,
  # The suites to run. The default holds the agent suites with the fewest
  # host assumptions. test_fim, test_logcollector, test_sca and
  # test_syscollector also target agents and can be added here, at the cost
  # of a much longer run and, likely, more upstream flakiness.
  suites ? [
    "test_agentd"
    "test_enrollment"
    "test_execd"
  ],
  # Extra arguments for every pytest invocation, for example
  # "--tier 0" or "--deselect test_agentd/test_state/test_agentd_state.py".
  extraPytestFlags ? "",
}:
let
  # Keep this pin in step with pkgs/wazuh-agent.nix, which documents the
  # submodule fallback. A plain `nix build` copies the repository without
  # submodule contents, and this fetch fills the gap.
  submodule = ../../modules/wazuh;
  haveSubmodule = builtins.pathExists (submodule + "/tests/integration/pytest.ini");
  testsSrc =
    if haveSubmodule then
      submodule + "/tests/integration"
    else
      "${
        pkgs.fetchFromGitHub {
          owner = "wazuh";
          repo = "wazuh";
          rev = "a42268a27c555d9348d5598fb8751eaf4c8e9024";
          sha256 = "sha256-GILu5/EvaN4XeeUqiz6cAFNiZHw0yAGbLuyUBxPrLj0=";
        }
      }/tests/integration";

  wazuhTesting = pkgs.callPackage ../../pkgs/wazuh-testing.nix { };
  pythonEnv = pkgs.python3.withPackages (_: [ wazuhTesting ]);

  # control_service() runs `service wazuh-agent <action>` and reads the exit
  # code. Map that onto wazuh-control, which is what service(8) reaches on
  # the distributions upstream tests on.
  serviceShim = pkgs.writeShellScriptBin "service" ''
    exec /var/ossec/bin/wazuh-control "$2"
  '';

  # The real wazuh-control computes DIR as the parent of the current working
  # directory, because the package build removed its `cd $LOCAL` line. The
  # framework calls it from the pytest working directory, which is wrong.
  # This wrapper pins the directory and exports WAZUH_HOME for the daemons
  # that wazuh-control forks. The test script moves the real script to
  # .wazuh-control-wrapped and puts this in its place.
  controlWrapper = pkgs.writeScript "wazuh-control-wrapper" ''
    #!/bin/sh
    export WAZUH_HOME=/var/ossec
    cd /var/ossec/bin
    exec /bin/sh ./.wazuh-control-wrapped "$@"
  '';
in
pkgs.testers.runNixOSTest {
  name = "wazuh-agent-integration";

  # The default is one hour, and the suites take longer.
  globalTimeout = 4 * 3600;

  nodes.agent =
    { pkgs, ... }:
    {
      imports = [ wazuhModule ];

      services.wazuh-agent = {
        enable = true;
        # The simulators listen on the loopback interface of this same VM.
        # Each test writes its own manager address anyway.
        manager.host = "127.0.0.1";

        # Keep active response enabled in the generated baseline. The
        # framework restarts every daemon through wazuh-control, execd exits
        # 0 when active response is disabled, and wazuh-control treats a
        # daemon that is gone after start as a start failure and exits 1.
        activeResponse.enable = true;
      };

      # The enrollment unit cannot succeed without a manager, so mark the
      # agent as registered before any unit starts. The suites create their
      # own client.keys entries through fixtures.
      systemd.tmpfiles.rules = [
        "f /var/ossec/.agent-registered 0640 wazuh wazuh -"
      ];

      environment.systemPackages = [
        pythonEnv
        serviceShim
        # wazuh-control finds daemons with ps, and several suites shell out
        # to standard tools.
        pkgs.procps
        # test_execd fires firewall-drop, whose binary resolves iptables on
        # the PATH of the execd process, which is the pytest PATH here.
        pkgs.iptables
      ];

      virtualisation = {
        memorySize = 4096;
        cores = 2;
        diskSize = 4096;
      };
    };

  testScript = ''
    suites = ${builtins.toJSON suites}
    extra_pytest_flags = ${builtins.toJSON extraPytestFlags}

    agent.wait_for_unit("multi-user.target")
    agent.wait_for_file("/var/ossec/etc/ossec.conf", timeout=120)

    with subtest("hand the daemons from systemd to the suite"):
        agent.succeed(
            "systemctl stop wazuh.target"
            " wazuh-agentd.service wazuh-logcollector.service"
            " wazuh-syscheckd.service wazuh-modulesd.service"
            " wazuh-execd.service"
        )

    with subtest("wazuh-control answers from any directory"):
        agent.succeed(
            "mv /var/ossec/bin/wazuh-control /var/ossec/bin/.wazuh-control-wrapped"
        )
        agent.succeed("cp ${controlWrapper} /var/ossec/bin/wazuh-control")
        agent.succeed("chmod 750 /var/ossec/bin/wazuh-control")
        agent_type = agent.succeed("cd / && /var/ossec/bin/wazuh-control info -t").strip()
        assert agent_type == "agent", f"wazuh-control info -t said {agent_type!r}"

    with subtest("the service shim drives the whole agent"):
        # wazuh-agentd exits when it has no key, and wazuh-control reports
        # that as a start failure. Give it one. The suites replace this file
        # through their own fixtures.
        agent.succeed(
            "echo '001 vm-plumbing-check any"
            " 6df50e48c825ca61af04ec1a4463affa8c1c57bbd0cbbc282d0a03d1b40b5b0b'"
            " > /var/ossec/etc/client.keys"
        )
        agent.succeed("service wazuh-agent restart >&2")
        agent.succeed("service wazuh-agent status >&2")
        agent.succeed("service wazuh-agent stop >&2")

    # The store copy is read only, and pytest writes reports and caches into
    # the test tree.
    agent.succeed("cp -r --no-preserve=mode ${testsSrc} /root/integration")

    failures = {}
    for suite in suites:
        with subtest(f"pytest {suite}"):
            agent.log(f"{suite} runs now. Expect a long wait.")
            status, _ = agent.execute(
                "cd /root/integration &&"
                " WAZUH_HOME=/var/ossec PYTHONDONTWRITEBYTECODE=1"
                f" python3 -m pytest {suite} -v --tb=short"
                f" --junitxml=report-{suite}.xml {extra_pytest_flags}"
                f" > log-{suite}.txt 2>&1",
                timeout=None,
            )
            agent.execute(f"tail -n 80 /root/integration/log-{suite}.txt >&2")
            for artifact in [f"report-{suite}.xml", f"log-{suite}.txt"]:
                if agent.execute(f"test -e /root/integration/{artifact}")[0] == 0:
                    agent.copy_from_machine(f"/root/integration/{artifact}")
            if status != 0:
                # A failed check discards its output, so the copied artifacts
                # are lost exactly when they matter. Put the failure section
                # in the driver log, which survives.
                agent.execute(
                    f"sed -n '/= FAILURES =/,$p' /root/integration/log-{suite}.txt"
                    " | head -n 400 >&2"
                )
                failures[suite] = status

    # The junit reports and full logs are in the check output either way.
    if failures:
        raise Exception(f"suites with failures (pytest exit codes): {failures}")
  '';
}
