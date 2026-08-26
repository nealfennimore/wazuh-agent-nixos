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
  # The suites to run. This is every agent-side suite the upstream tree
  # holds. test_fim dominates the run time. suiteFlags below carries the
  # per-suite exclusions, with the reason next to each one.
  suites ? [
    "test_agentd"
    "test_enrollment"
    "test_execd"
    "test_fim"
    "test_logcollector"
    "test_sca"
    "test_syscollector"
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

  # Arguments that one suite needs and the others must not see. Each entry
  # carries the reason it exists. Three classes appear so far: tests that need
  # audit infrastructure NixOS cannot provide, single cases that lose a
  # timing race inside a VM, and tests of a response this flake removes on
  # purpose.
  suiteFlags = {
    # The whole file drives the restart-wazuh response and asserts on the
    # execd shutdown log it causes. This flake removes restart-wazuh and
    # restart.sh from the package output, because they start daemons outside
    # systemd (see noExecStateDirsFor in nixos/wazuh-agent/default.nix). The
    # response is absent by design, so the test can only fail.
    test_execd = "--ignore=test_execd/test_run_active_response/test_restart_wazuh.py";

    test_fim = builtins.concatStringsSep " " [
      # whodata mode needs the audit daemon with the audisp-af_unix plugin,
      # and syscheck_audit.c writes a plugin file that names
      # /sbin/audisp-af_unix, a path NixOS does not have. The whodata cases
      # can only time out here, and there are about 165 of them at 30
      # seconds each, so filter them by their case ids. The three spellings
      # match the three forms the case names use.
      "-k 'not whodata and not Whodata and not Who-data'"

      # Removes and reinstalls the audit package with yum or apt, and NixOS
      # has neither.
      "--ignore=test_fim/test_files/test_audit"

      # Runs `auditctl -l` from the test body in every mode, and asserts on
      # the whodata audit rules, so it is audit infrastructure in the same
      # class as test_audit.
      "--ignore=test_fim/test_files/test_follow_symbolic_link/test_audit_rules_with_symlink.py"

      # Creates one hundred thousand files and waits for the file-limit log
      # with a fixed monitor timeout. A VM does not create them in time. The
      # 80 and 90 percent cases stay, and they cover the same code path.
      ''--deselect "test_fim/test_files/test_file_limit/test_fill_capacity.py::test_fill_capacity[Default file limit fill 100% - Real-time]"''

      # In realtime mode the baseline snapshot races the writes the test
      # makes. On a slow VM the baseline lands after the change, diff then
      # reports no content change, and the assertion on "More changes..."
      # fails. The scheduled cases cover the same assertion and pass.
      ''--deselect "test_fim/test_files/test_report_changes/test_disk_quota_disabled.py::test_disk_quota_disabled[Test 'disk_quota' information, fim_mode = realtime]"''
      ''--deselect "test_fim/test_files/test_report_changes/test_file_size_disabled.py::test_file_size_disabled[Test 'disk_quota' information, fim_mode = realtime]"''
    ];
  };

  wazuhTesting = pkgs.callPackage ../../pkgs/wazuh-testing.nix { };
  pythonEnv = pkgs.python3.withPackages (_: [ wazuhTesting ]);

  # test_fim/conftest.py holds a session-scoped autouse fixture that
  # installs auditd with yum or apt and raises ValueError on every other
  # distribution, which fails every test in the suite before it starts.
  # Replace the fixture body with a no-op. The whodata cases are the only
  # ones that need audit, and suiteFlags filters them out.
  #
  # The anchors are exact strings, so an upstream change to the fixture
  # fails this build with a clear message rather than drifting silently.
  disableInstallAudit = pkgs.writeText "disable-install-audit.py" ''
    import sys
    from pathlib import Path

    conftest = Path(sys.argv[1]) / "test_fim" / "conftest.py"
    text = conftest.read_text()
    try:
        start = text.index("def install_audit():")
        end = text.index("@pytest.fixture()", start)
    except ValueError:
        sys.exit(
            "disable-install-audit: the install_audit fixture moved in "
            f"{conftest}. Update nixos/tests/integration.nix."
        )
    replacement = (
        "def install_audit():\n"
        '    """Do nothing. Upstream installs auditd with yum or apt here,\n'
        "    and the NixOS check filters out the whodata cases, which are\n"
        "    the only ones that need audit.\n"
        '    """\n'
        "\n\n"
    )
    conftest.write_text(text[:start] + replacement + text[end:])
  '';

  patchedTests = pkgs.runCommand "wazuh-integration-tests" { } ''
    cp -r ${testsSrc} $out
    chmod -R u+w $out
    ${pkgs.python3}/bin/python3 ${disableInstallAudit} $out
  '';

  # The real wazuh-control computes DIR as the parent of the current working
  # directory, because the package build removed its `cd $LOCAL` line. The
  # framework calls it from the pytest working directory, which is wrong.
  # This wrapper pins the directory and exports WAZUH_HOME for the daemons
  # that wazuh-control forks. Keep it in the store: /var/ossec/bin is now an
  # immutable store link and test instrumentation must not rewrite it.
  controlWrapper = pkgs.writeScript "wazuh-control-wrapper" ''
    #!/bin/sh
    export WAZUH_HOME=/var/ossec
    cd /var/ossec/bin
    exec /bin/sh ./wazuh-control "$@"
  '';

  # control_service() runs `service wazuh-agent <action>` and reads the exit
  # code. Map that onto the wrapper above, which in turn reaches the immutable
  # wazuh-control script. A few fixtures use service(8) for other units, so
  # anything else goes to systemctl with the argument order swapped.
  serviceShim = pkgs.writeShellScriptBin "service" ''
    case "$1" in
      wazuh-agent | wazuh-manager)
        exec ${controlWrapper} "$2"
        ;;
      *)
        exec systemctl "$2" "$1"
        ;;
    esac
  '';
in
pkgs.testers.runNixOSTest {
  name = "wazuh-agent-integration";

  # The default is one hour. The full suite list runs for several hours,
  # and test_fim is most of that.
  globalTimeout = 12 * 3600;

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
        # test_fim writes diff copies under queue/diff and the pytest logs
        # grow with the case count.
        diskSize = 8192;
      };
    };

  testScript = ''
    suites = ${builtins.toJSON suites}
    extra_pytest_flags = ${builtins.toJSON extraPytestFlags}
    suite_flags = ${builtins.toJSON suiteFlags}

    agent.wait_for_unit("multi-user.target")
    agent.wait_for_file("/var/ossec/etc/ossec.conf", timeout=120)

    with subtest("hand the daemons from systemd to the suite"):
        agent.succeed(
            "systemctl stop wazuh.target"
            " wazuh-agentd.service wazuh-logcollector.service"
            " wazuh-syscheckd.service wazuh-modulesd.service"
            " wazuh-execd.service"
        )

    with subtest("hand the suite-owned files from the store to the suite"):
        # The module links etc/ossec.conf and ruleset into the read-only
        # store. The suite opens ossec.conf "r+" to rewrite it between
        # tests, and test_sca swaps policy files inside ruleset/sca, so
        # both must be mutable here. Replace the links with real copies.
        # The daemons run as root under the suite and read the copies the
        # same way. checks.agent is what proves the immutable layout.
        agent.succeed(
            "cp -L /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.rw"
            " && mv /var/ossec/etc/ossec.conf.rw /var/ossec/etc/ossec.conf"
            " && chmod 640 /var/ossec/etc/ossec.conf"
        )
        # The module treats ruleset as optional, hence the guard.
        agent.succeed(
            "if [ -L /var/ossec/ruleset ]; then"
            " ruleset=$(readlink -f /var/ossec/ruleset)"
            " && rm /var/ossec/ruleset"
            ' && cp -r --no-preserve=mode,ownership "$ruleset" /var/ossec/ruleset;'
            " fi"
        )

    with subtest("wazuh-control answers from any directory"):
        agent_type = agent.succeed("cd / && ${controlWrapper} info -t").strip()
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
    agent.succeed("cp -r --no-preserve=mode ${patchedTests} /root/integration")

    failures = {}
    for suite in suites:
        with subtest(f"pytest {suite}"):
            agent.log(f"{suite} runs now. Expect a long wait.")
            flags = (extra_pytest_flags + " " + suite_flags.get(suite, "")).strip()
            status, _ = agent.execute(
                "cd /root/integration &&"
                " WAZUH_HOME=/var/ossec PYTHONDONTWRITEBYTECODE=1"
                f" python3 -m pytest {suite} -v --tb=short"
                f" --junitxml=report-{suite}.xml {flags}"
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
