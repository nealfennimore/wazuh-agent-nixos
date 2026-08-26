{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  wazuhUser = "wazuh";
  wazuhGroup = wazuhUser;
  stateDir = "/var/ossec";
  enrollmentPasswordCredential = "wazuh-agent-auth-password";
  cfg = config.services.wazuh-agent;
  pkg = cfg.package;
  configuredXml = optionalString (cfg.config != null) cfg.config + cfg.extraConfig;
  storeUnsafeWodles = [
    "aws-s3"
    "azure-logs"
    "gcloud-pubsub"
    "docker-listener"
  ];

  generatedConfig =
    if cfg.config != null then
      pkgs.writeText "ossec.conf" cfg.config
    else
      import ./generate-agent-config.nix { inherit cfg pkgs; };

  # /var/ossec holds package content and host state in one tree, so the
  # directories divide three ways. The previous version copied all of them only
  # when they were absent, which meant an upgrade kept the old package's files
  # forever.

  # Owned wholly by the package. These names are links into the Nix store;
  # no activation-time copy is needed and an upgrade changes the link target.
  immutablePackageDirs = [
    "agentless"
    "bin"
    "lib"
    "wodles"
  ];

  # Also owned by the package, but not every build produces them.
  #
  # ruleset holds the SCA policies. install.sh creates ruleset/sca in
  # InstallCommon, then fills it only when it recognizes the distribution, and
  # it does not recognize NixOS. A build that matched nothing leaves the
  # directory absent, so the copy is conditional rather than mandatory.
  optionalImmutablePackageDirs = [
    "ruleset"
  ];

  # Owned by the host. Created once from the package skeleton, then left alone.
  # These hold the agent's databases, queues and logs.
  stateDirs = [
    "logs"
    "queue"
    "tmp"
    "var"
  ];

  # etc holds both, so it is refreshed name by name. These are the names the
  # host owns; everything else in etc follows the package.
  #
  # The split is upstream's own. src/init/inst-functions.sh installs
  # internal_options.conf unconditionally, and installs client.keys,
  # local_internal_options.conf and ossec.conf only when they are absent.
  # etc/shared is created empty and filled by the manager.
  hostOwnedEtc = [
    "authd.pass"
    "client.keys"
    "local_internal_options.conf"
    "ossec.conf"
    "shared"
  ];

  preStart = ''
    # The fixed layout belongs to root. Package trees point straight into the
    # store instead of being mutable copies owned by the daemon account.
    if [ -L ${stateDir} ]; then
      rm ${stateDir}
    fi
    install -d -m 0750 -o root -g ${wazuhGroup} ${stateDir}
    ${concatMapStringsSep "\n" (dir: ''
      rm -rf ${stateDir}/${dir}
      ln -s ${pkg}/${dir} ${stateDir}/${dir}
    '') immutablePackageDirs}
    ${concatMapStringsSep "\n" (dir: ''
      if [ -d ${pkg}/${dir} ]; then
        rm -rf ${stateDir}/${dir}
        ln -s ${pkg}/${dir} ${stateDir}/${dir}
      else
        rm -rf ${stateDir}/${dir}
      fi
    '') optionalImmutablePackageDirs}

    ${concatMapStringsSep "\n" (
      dir:
      ''
        if [ -L ${stateDir}/${dir} ]; then
          rm ${stateDir}/${dir}
        fi
        [ -d ${stateDir}/${dir} ] || cp -R --no-preserve=ownership,mode ${pkg}/${dir} ${stateDir}/${dir}
      ''
    ) stateDirs}

    # active-response/bin must remain a real sticky directory: three response
    # programs create mutex directories beside themselves. The programs are
    # root-owned store links, so the wazuh group can create locks but cannot
    # replace executable entries.
    if [ -L ${stateDir}/active-response ]; then
      rm ${stateDir}/active-response
    fi
    install -d -m 0750 -o root -g ${wazuhGroup} ${stateDir}/active-response
    install -d -m 1770 -o root -g ${wazuhGroup} ${stateDir}/active-response/bin
    # Keep the directory inode, because it is a writable mount point in a
    # running execd namespace, but keep no entry inside it. In particular, an
    # attacker-staged symlink would resolve onto an executable store inode and
    # must not persist across activation.
    find ${stateDir}/active-response/bin -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    for entry in ${pkg}/active-response/bin/*; do
      [ -e "$entry" ] || continue
      name="$(basename "$entry")"
      rm -rf ${stateDir}/active-response/bin/"$name"
      ln -s "$entry" ${stateDir}/active-response/bin/"$name"
    done
    rm -f ${stateDir}/active-response/bin/restart-wazuh \
      ${stateDir}/active-response/bin/restart.sh

    # etc is mixed. Its directory is sticky and root-owned; mutable host files
    # belong to wazuh, while package files and generated ossec.conf are store
    # links that the daemon UID cannot replace.
    if [ -L ${stateDir}/etc ]; then
      rm ${stateDir}/etc
    fi
    install -d -m 1770 -o root -g ${wazuhGroup} ${stateDir}/etc
    if [ -L ${stateDir}/etc/shared ]; then
      rm ${stateDir}/etc/shared
    fi
    install -d -m 0750 -o ${wazuhUser} -g ${wazuhGroup} ${stateDir}/etc/shared
    touch ${stateDir}/etc/audit_rules_wazuh.rules
    chown ${wazuhUser}:${wazuhGroup} ${stateDir}/etc/audit_rules_wazuh.rules
    chmod 0640 ${stateDir}/etc/audit_rules_wazuh.rules
    for name in client.keys local_internal_options.conf; do
      if [ -L ${stateDir}/etc/"$name" ]; then
        rm ${stateDir}/etc/"$name"
      fi
      if [ ! -e ${stateDir}/etc/"$name" ] && [ -e ${pkg}/etc/"$name" ]; then
        cp -R --no-preserve=ownership,mode ${pkg}/etc/"$name" ${stateDir}/etc/"$name"
      fi
      if [ -e ${stateDir}/etc/"$name" ]; then
        chown ${wazuhUser}:${wazuhGroup} ${stateDir}/etc/"$name"
        chmod 0640 ${stateDir}/etc/"$name"
      fi
    done

    # Refresh the package's own files in etc. Without this a version bump keeps
    # the previous internal_options.conf, and wazuh-modulesd exits 1 with
    # "(2301): Definition not found for:" naming the first key the new version
    # added. wazuh_modules.rlimit_nofile arrived in 4.13.0, so an agent whose
    # /var/ossec predates that never starts modulesd again.
    for entry in ${pkg}/etc/*; do
      [ -e "$entry" ] || continue
      case "$(basename "$entry")" in
        ${concatStringsSep " | " hostOwnedEtc}) ;;
        *)
          name="$(basename "$entry")"
          rm -rf ${stateDir}/etc/"$name"
          ln -s "$entry" ${stateDir}/etc/"$name"
          ;;
      esac
    done

    # norm_config.json ships with the package but lives under queue, which is
    # otherwise state. inst-functions.sh reinstalls it on every upgrade too.
    if [ -f ${pkg}/queue/syscollector/norm_config.json ]; then
      install -d -m 0750 -o ${wazuhUser} -g ${wazuhGroup} ${stateDir}/queue/syscollector
      rm -f ${stateDir}/queue/syscollector/norm_config.json
      ln -s ${pkg}/queue/syscollector/norm_config.json \
        ${stateDir}/queue/syscollector/norm_config.json
    fi

    chown -R ${wazuhUser}:${wazuhGroup} ${concatStringsSep " " (map (dir: "${stateDir}/${dir}") stateDirs)}
    find ${concatStringsSep " " (map (dir: "${stateDir}/${dir}") stateDirs)} -type d -exec chmod 750 {} +
    find ${concatStringsSep " " (map (dir: "${stateDir}/${dir}") stateDirs)} -type f -exec chmod 640 {} +

    rm -f ${stateDir}/etc/ossec.conf
    ln -s ${generatedConfig} ${stateDir}/etc/ossec.conf

    ${optionalString (cfg.agentAuthPasswordFile != null) ''
      # PID 1 reads the configured source before this service changes to the
      # wazuh user. This supports the 0400 root-owned files that secret
      # managers create without weakening the source file's ownership or mode.
      if [ -L ${stateDir}/etc/authd.pass ]; then
        rm ${stateDir}/etc/authd.pass
      fi
      install -o ${wazuhUser} -g ${wazuhGroup} -m 0640 \
        "$CREDENTIALS_DIRECTORY/${enrollmentPasswordCredential}" \
        ${stateDir}/etc/authd.pass
    ''}
  '';

  # wazuh-execd is conditional. With active response disabled it reads the
  # configuration, logs "Active response disabled" and returns 0
  # (src/os_execd/execd.c:574-577). A unit that exits cleanly at start is not
  # a failure, but it is a unit that reports inactive forever, so do not
  # define one that has nothing to do.
  daemons = [
    "wazuh-modulesd"
    "wazuh-logcollector"
    "wazuh-syscheckd"
    "wazuh-agentd"
  ]
  ++ optional cfg.activeResponse.enable "wazuh-execd";

  # The directories under /var/ossec that the daemons write. Everything
  # else in the state directory, including the package trees bin, lib,
  # ruleset, wodles and agentless, stays read-only through ProtectSystem =
  # "strict": the root of the namespace is read-only, and only these paths
  # get a writable bind mount.
  #
  # The list points in this direction on purpose. An earlier version kept
  # the whole of /var/ossec writable and stacked ReadOnlyPaths mounts over
  # the package trees. checks.agent caught those mounts vanishing, and the
  # mechanism is the kernel: deleting a mountpoint directory detaches the
  # mounts every namespace holds on it, and setup-pre-wazuh deleted
  # exactly those directories on every activation during its refresh. A
  # detached read-only mount fails open, silently. A detached writable
  # bind fails closed: the daemon cannot write its state, and says so. So
  # the read-only guarantee rests on the root remount, which nothing
  # detaches, the writable binds sit on directories the refresh keeps (see
  # the note at preStart), and only the writable side depends on child
  # mounts at all.
  #
  # Every unit's writable list carries NoExecPaths as well, so writable and
  # executable never overlap. Response entries are symlinks into the Nix
  # store: they resolve onto the executable store mount, while an ordinary
  # file staged beside them stays on the noexec active-response mount. The
  # response libraries resolve from the store through $ORIGIN/../../lib.
  #
  # The writable set is per unit, not shared. A directory that only one
  # unit writes is read-only in the other four, so a compromise of one
  # daemon does not reach what another daemon runs.
  #
  # These four are the state every daemon keeps: its databases, its
  # queues, its logs and its scratch space.
  sharedWritableDirs = [
    "logs"
    "queue"
    "var"
    "tmp"
  ];

  # Writable in the units that write them, and read-only everywhere else.
  # Both of these were shared until now, and both decide what the agent
  # runs, so a compromise of any one daemon reached the privilege of
  # another through them.
  #
  # etc holds two files that select a program. etc/ossec.conf takes a
  # <localfile> with <log_format>command</log_format>, which makes
  # wazuh-logcollector run any command. Upstream treats that as a privilege
  # boundary and refuses such an entry when it arrives from the manager
  # (src/config/localfile-config.c, "Remote commands are not accepted from
  # the manager"), and the local file is always accepted. etc/shared/ar.conf
  # is DEFAULTAR (src/headers/defs.h), and it maps a response name to a
  # binary under active-response/bin. NoExecPaths does not reach either: the
  # command a <localfile> names runs from /nix/store or
  # /run/current-system/sw, outside the state directory.
  #
  # Two units write etc. wazuh-agent-auth writes etc/client.keys, and
  # wazuh-agentd writes it too when the manager triggers a re-enrollment,
  # plus etc/shared/merged.mg when the manager pushes shared configuration.
  # wazuh-logcollector, wazuh-syscheckd, wazuh-modulesd and wazuh-execd read
  # etc and do not write it, so they lose the write.
  #
  # active-response is where wazuh-execd runs response programs from, with
  # CAP_NET_ADMIN or, under disable-account, as root. Nothing else in the
  # module touches it. So only wazuh-execd keeps the write, which narrows
  # the reach from any daemon to the one unit that already holds the
  # privilege. The residual hole above is unchanged: wazuh-execd can still
  # rewrite what wazuh-execd runs.
  #
  # setup-pre-wazuh is not here. It refreshes every package directory and
  # writes the whole state directory, through the ProtectSystem = "full"
  # at its own unit.
  unitWritableDirs =
    unit:
    optional (unit == "wazuh-agentd" || unit == "wazuh-agent-auth") "etc"
    ++ optional (unit == "wazuh-execd") "active-response";

  writableStateDirsFor =
    unit: map (dir: "${stateDir}/${dir}") (sharedWritableDirs ++ unitWritableDirs unit);

  # syscheckd writes this one file when whodata is enabled while auditd is in
  # immutable mode. A file bind preserves that configuration without making
  # the execution-controlling files beside it writable.
  writableStateFilesFor =
    unit: optional (unit == "wazuh-syscheckd") "${stateDir}/etc/audit_rules_wazuh.rules";

  # restart-wazuh and restart.sh are removed from the package output. They
  # start daemons outside systemd and were the only reason execd needed a
  # child NoExecPaths mount on bin. Removing them closes the path without a
  # mount on a store-link inode that activation must replace on upgrades.
  noExecStateDirsFor = unit: writableStateDirsFor unit ++ writableStateFilesFor unit;

  # Sandboxing shared by every unit in this module.
  #
  # Read the "deliberately absent" list at the bottom before adding to this.
  # Several of the usual hardening options break what the agent is for, and one
  # of them fails by reporting findings that are not real.
  hardening = {
    # The daemons no longer drop privileges themselves. The privsep patch in
    # pkgs/patches makes Privsep_SetUser and Privsep_SetGroup return success
    # without calling setuid or setgroups, because systemd has already put the
    # process where it belongs. So there is nothing left that needs a
    # capability, and CAP_SETGID can go.
    CapabilityBoundingSet = [ "" ];
    AmbientCapabilities = [ "" ];
    NoNewPrivileges = true;

    # The state directories are the only thing the agent writes, and
    # nothing writable is a program to run: a payload staged in queue,
    # logs or tmp cannot be executed. The package trees stay read-only
    # through the strict root. See the sharedWritableDirs note above for
    # why the writable side is the enumerated one.
    #
    # These two are the narrowest set any unit gets. Every unit that needs
    # more replaces them through writableStateDirsFor and
    # noExecStateDirsFor, so a unit added without a thought about etc or
    # active-response fails closed rather than open.
    ProtectSystem = "strict";
    ReadWritePaths = map (dir: "${stateDir}/${dir}") sharedWritableDirs;
    NoExecPaths = map (dir: "${stateDir}/${dir}") sharedWritableDirs;

    # read-only, not true. File integrity monitoring must still be able to read
    # /root and /home, which syscheck.directories documents as a reasonable
    # thing to add. ProtectHome = true replaces both with empty directories,
    # and syscheck reports no error when it monitors an empty directory.
    ProtectHome = "read-only";

    PrivateTmp = true;
    ProtectClock = true;
    ProtectControlGroups = true;
    ProtectHostname = true;
    ProtectKernelLogs = true;
    ProtectKernelModules = true;
    ProtectKernelTunables = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    RemoveIPC = true;
    SystemCallArchitectures = "native";
    UMask = "0027";

    # The four below were parked as plausible and untested. They are on now,
    # and checks.enrollment is what tests them: it asserts that syscollector,
    # SCA and rootcheck each finish a scan, and that no daemon died of SIGSYS.
    # A restriction that breaks one of these does not stop the daemon, it
    # stops the scan, so `systemctl is-active` cannot see it.

    # The agent talks to the manager over IP, to its own daemons over Unix
    # sockets, and to the kernel over netlink, which is how syscollector reads
    # the network inventory. It needs no other family.
    RestrictAddressFamilies = [
      "AF_UNIX"
      "AF_INET"
      "AF_INET6"
      "AF_NETLINK"
    ];

    # No component maps a page both writable and executable. The risk here was
    # the python wodles, and none of them is enabled in the generated
    # configuration.
    MemoryDenyWriteExecute = true;

    # Hardware inventory reads /proc and /sys, not device nodes.
    PrivateDevices = true;

    # bpf is in @privileged, not in @system-service, so file integrity
    # monitoring in whodata mode would need an exception. The generated
    # configuration uses scheduled mode, which does not load the eBPF object.
    SystemCallFilter = [ "@system-service" ];
  };

  # Deliberately absent, and the reasons matter more than the list.
  #
  # ProtectProc, ProcSubset, PrivateUsers and PrivatePIDs all hide or remap
  # other processes. rootcheck detects a hidden process by comparing two views
  # of the same PID: kill(pid, 0) and getsid(pid) against stat, opendir and
  # readdir on /proc/<pid>, in src/rootcheck/check_rc_pids.c. A disagreement is
  # what it reports. Any of these options creates that disagreement for every
  # process on the host, so the agent does not fail. It reports the whole
  # process table as hidden processes. A hardening option that manufactures
  # security findings is worse than no hardening option.
  #
  # ProtectHome = true would make /root and /home empty rather than
  # unreadable, and syscheck logs no error when it monitors an empty
  # directory. read-only above keeps those two usable as FIM targets.
  #
  # SocketBindDeny is absent because Wazuh binds on purpose before every
  # outbound connection. OS_Connect in src/os_net/os_net.c binds the
  # client socket to INADDR_ANY port 0 ("Force a new ephemeral port
  # before connecting") before it calls connect, for TCP and UDP and for
  # both address families. A bind deny therefore cuts the agent off from
  # its manager: checks.enrollment failed with "(1208): Unable to connect
  # to enrollment service" in agent-auth and agentd alike. Allowing only
  # the port-0 bind is no fix, because a compromised daemon can bind port
  # 0 and listen on whatever ephemeral port it gets, which is the exact
  # thing the deny was for.
  #
  # SystemCallFilter, MemoryDenyWriteExecute, RestrictAddressFamilies and
  # PrivateDevices are no longer in this list. They are applied above, and the
  # note there says what tests them.

  # What each active response needs, granted per response rather than as one
  # block. Only wazuh-execd runs them, so nothing here reaches another unit.
  #
  # Each script resolves its binary through get_binary_path, which is a PATH
  # lookup, and a miss is written to logs/active-responses.log rather than to
  # the journal. So a response that is selected without its binary fails in a
  # place the agent's own log never shows.
  # This table is the single source for both the options below and the grants
  # they produce. Adding a response here adds
  # services.wazuh-agent.activeResponse.capability.<name>.enable with it.
  responseRequirements = {
    # Adds INPUT and FORWARD DROP rules. iptables supplies ip6tables too.
    # firewalls/default-firewall-drop.c:89
    firewall-drop = {
      default = true;
      description = "Add the offending address to the iptables DROP list.";
      packages = [ pkgs.iptables ];
      capabilities = [ "CAP_NET_ADMIN" ];
      readWritePaths = [ ];
      tmpfiles = [ ];
      polkit = "";
      runAsRoot = false;
    };

    # Adds a reject route. Note that it resolves "route" and not "ip"
    # (route-null.c:67), so nettools in the path default already covers it.
    route-null = {
      default = true;
      description = "Route the offending address to nowhere.";
      packages = [ pkgs.nettools ];
      capabilities = [ "CAP_NET_ADMIN" ];
      readWritePaths = [ ];
      tmpfiles = [ ];
      polkit = "";
      runAsRoot = false;
    };

    # Posts to a webhook. No capability at all, only a binary.
    # wazuh-slack.c:79,105
    wazuh-slack = {
      default = true;
      description = ''
        Post a notification to a Slack webhook. This one needs no capability,
        only curl. The webhook URL comes from the manager as extra_args.
      '';
      packages = [ pkgs.curl ];
      capabilities = [ ];
      readWritePaths = [ ];
      tmpfiles = [ ];
      polkit = "";
      runAsRoot = false;
    };

    # Appends to /etc/hosts.deny, and the path is hardcoded on Linux
    # (host-deny.c:14,81). Two things block it and neither is a capability:
    # ProtectSystem = "strict" makes /etc read-only, and the file is root
    # owned. So punch a hole for that one path and create the file owned by
    # the wazuh user. The leading - tolerates its absence at unit start.
    host-deny = {
      default = false;
      description = ''
        Append the offending address to /etc/hosts.deny.

        Off by default, because the grant is a different shape from the
        others. The path is hardcoded, ProtectSystem = "strict" makes /etc
        read-only, and the file is normally owned by root. Enabling this adds
        /etc/hosts.deny to ReadWritePaths for wazuh-execd alone and creates
        the file owned by the wazuh user. Neither of those is a capability.

        Little reads /etc/hosts.deny on a modern NixOS host. Enable this only
        if something on yours does.
      '';
      packages = [ ];
      capabilities = [ ];
      readWritePaths = [ "-/etc/hosts.deny" ];
      tmpfiles = [ "f /etc/hosts.deny 0644 ${wazuhUser} ${wazuhGroup} -" ];
      polkit = "";
      runAsRoot = false;
    };

    # Adds a runtime rich rule (firewalld-drop.c:66,88,121):
    #   firewall-cmd --add-rich-rule 'rule family=ipv4 source address=X drop'
    #
    # The binary is not the problem. services.firewalld puts its package in
    # environment.systemPackages, so firewall-cmd is already on the daemon
    # PATH through /run/current-system/sw. Authorization is the problem:
    # firewall-cmd talks to firewalld over the system bus, and polkit gates
    # a runtime change behind org.fedoraproject.FirewallD1.all.
    #
    # That action id reads broader than it is narrow. It covers every runtime
    # change firewalld accepts, not only rich rules, because firewalld does
    # not split runtime authorization any finer. Permanent changes are a
    # different action and this rule does not grant them.
    firewalld-drop = {
      default = config.services.firewalld.enable or false;
      description = ''
        Add the offending address to the firewalld drop list.

        Defaults to whether services.firewalld is enabled, so it follows the
        host rather than needing to be kept in step by hand. It does nothing
        without firewalld running.

        This adds a polkit rule letting the wazuh user call
        org.fedoraproject.FirewallD1.all, which is every runtime change
        firewalld accepts. firewalld does not split runtime authorization
        more finely than that. Permanent changes are a separate action and
        stay denied.
      '';
      packages = [ ];
      capabilities = [ ];
      readWritePaths = [ ];
      tmpfiles = [ ];
      polkit = ''
        polkit.addRule(function(action, subject) {
          if (action.id == "org.fedoraproject.FirewallD1.all" &&
              subject.user == "${wazuhUser}") {
            return polkit.Result.YES;
          }
        });
      '';
      runAsRoot = false;
    };

    # Runs `passwd -l` (disable-account.c:67,78). This one is not a
    # capability, and that is the whole point of the warning it carries.
    #
    # shadow takes amroot from the real UID (passwd.c:71,767) and refuses the
    # flag when it is not 0 (passwd.c:972). No capability changes getuid, and
    # a setuid wrapper only changes the effective UID. So the only way to
    # reach this response is to run wazuh-execd as root.
    #
    # Group stays wazuh rather than root. execd and the scripts it forks
    # write logs/active-responses.log, and UMask 0027 would otherwise leave
    # that file root:root 0640, which wazuh-logcollector could not read. The
    # reader is how the manager learns a response ran at all.
    disable-account = {
      default = false;
      description = ''
        Lock the offending user account with `passwd -l`.

        This one runs wazuh-execd as root. It is not a capability grant and
        no capability can substitute: shadow reads the real UID, so neither
        a capability nor a setuid wrapper reaches it.

        Enabling this gives up the privilege separation the rest of this
        module is built on, for that one unit. /etc becomes writable to it,
        because passwd rewrites shadow through a temporary file and a lock in
        the same directory. The module warns at evaluation when this is on.

        The unit keeps the wazuh group, so logs/active-responses.log stays
        readable by wazuh-logcollector.
      '';
      packages = [ pkgs.shadow ];
      capabilities = [
        "CAP_CHOWN"
        "CAP_DAC_OVERRIDE"
        "CAP_FOWNER"
      ];
      readWritePaths = [ "/etc" ];
      tmpfiles = [ ];
      polkit = "";
      runAsRoot = true;
    };
  };

  # The rest of what the package ships has no option here:
  #
  #   restart-wazuh    restarts through wazuh-control, which starts daemons
  #   restart.sh       outside the supervision systemd already provides.
  #   ipfw, npf, pf    BSD firewalls.
  #   kaspersky        needs a vendor CLI that is not packaged here.
  #   ip-customblock   is a stub for the operator to write. It appends under
  #                    active-response/bin, which is already writable, so it
  #                    needs nothing from this table.

  # Guarded on enable, so that capability settings left behind grant nothing
  # and create nothing while active response is off.
  selectedResponses = optionals cfg.activeResponse.enable (
    attrValues (
      filterAttrs (name: _: cfg.activeResponse.capability.${name}.enable) responseRequirements
    )
  );
  gather = attr: unique (concatMap (r: r.${attr}) selectedResponses);

  execdPackages = gather "packages";
  execdCapabilities = gather "capabilities";

  # Only disable-account sets this, and it cannot be reached any other way.
  # See its entry above.
  execdRunsAsRoot = any (r: r.runAsRoot) selectedResponses;

  execdPolkit = concatStringsSep "\n" (filter (s: s != "") (map (r: r.polkit) selectedResponses));

  execdHardening = optionalAttrs (execdCapabilities != [ ]) {
    CapabilityBoundingSet = execdCapabilities;
    AmbientCapabilities = execdCapabilities;
  };

  mkService = d: {
    description = d;
    wants = [ "wazuh-agent-auth.service" ];

    partOf = [ "wazuh.target" ];
    # Every entry here goes through lib.makeBinPath, which appends /bin, and
    # through makeSearchPathOutput, which appends /sbin. So an entry must name
    # the prefix, not the bin directory.
    #
    # The previous version named "/run/current-system/sw/bin" and produced
    # "/run/current-system/sw/bin/bin", which does not exist. The system path
    # was therefore absent from the daemon PATH, and nothing said so. What hid
    # it is that NixOS adds coreutils, findutils, gnugrep, gnused and systemd
    # to every service path by default, so the commands the agent runs kept
    # resolving.
    path =
      cfg.path
      ++ optionals (d == "wazuh-execd" && cfg.activeResponse.enable) execdPackages
      ++ [
        "/run/current-system/sw"
        "/run/wrappers"
      ];
    environment = {
      WAZUH_HOME = stateDir;
    };

    serviceConfig =
      hardening
      # syscheckd creates and binds sockets for the rootcheck port probe,
      # but the probe closes each socket right after the bind and never
      # sends a packet (src/rootcheck/check_rc_ports.c), and nothing else
      # in syscheckd or rootcheck uses the network. The manager path runs
      # through agentd over a Unix socket. So syscheckd keeps bind() and
      # loses IP traffic. The other daemons keep their traffic: agentd
      # talks to the manager, and logcollector and modulesd run reader
      # commands and wodles that a host configuration can point at the
      # network.
      // optionalAttrs (d == "wazuh-syscheckd") {
        IPAddressDeny = "any";
      }
      // optionalAttrs (d == "wazuh-execd") execdHardening
      // {
        # Per unit rather than shared. A response may need a path outside
        # the state directory, and only wazuh-execd runs responses.
        ReadWritePaths =
          writableStateDirsFor d
          ++ writableStateFilesFor d
          ++ optionals (d == "wazuh-execd") (gather "readWritePaths");
        NoExecPaths = noExecStateDirsFor d;

        Type = "exec";

        # Root only when a selected response cannot be reached any other way,
        # which today means disable-account alone. The group stays wazuh either
        # way: execd and the scripts it forks write logs/active-responses.log,
        # and UMask 0027 under root:root would leave a file wazuh-logcollector
        # could not read, which is how the manager learns a response ran.
        User = if (d == "wazuh-execd" && execdRunsAsRoot) then "root" else wazuhUser;
        Group = wazuhGroup;
        WorkingDirectory = "${stateDir}/";

        # Straight from the store. These used to run through a setuid wrapper,
        # which gave every local user a way to execute them as the wazuh user,
        # the account that owns client.keys. The wrapper bought nothing: systemd
        # already sets User and Group, and the w_homedir patch makes the daemons
        # read WAZUH_HOME from the environment instead of resolving
        # /proc/self/exe, which is the other reason a wrapper was once useful.
        # agent-auth has always started from the store path this way.
        ExecStart =
          if d != "wazuh-modulesd" then
            "${pkg}/bin/${d} -f -c ${stateDir}/etc/ossec.conf"
          else
            "${pkg}/bin/${d} -f";
      };
  };
in
{
  options.services.wazuh-agent = {
    enable = mkEnableOption "Wazuh agent";

    package = mkPackageOption pkgs "wazuh-agent" { };

    manager = mkOption {
      description = "The Wazuh manager this agent reports to.";
      type = types.submodule {
        freeformType =
          with types;
          attrsOf (oneOf [
            nonEmptyStr
            port
          ]);
        options = {
          host = mkOption {
            type = types.nonEmptyStr;
            description = "The IP address or hostname of the manager.";
            example = "192.168.1.2";
          };
          port = mkOption {
            type = types.port;
            description = "The port the manager listens on for agent traffic.";
            example = 1514;
            default = 1514;
          };
        };
      };
    };

    registration = mkOption {
      description = ''
        The enrollment server. When host is null, the agent enrolls against
        the manager instead.
      '';
      default = { };
      type = types.submodule {
        freeformType =
          with types;
          attrsOf (oneOf [
            nonEmptyStr
            port
          ]);
        options = {
          host = mkOption {
            type = types.nullOr types.nonEmptyStr;
            description = "The IP address or hostname of the registration server.";
            example = "192.168.1.2";
            default = null;
          };
          port = mkOption {
            type = types.port;
            description = ''
              The port that authd listens on for enrollment. The agent uses
              this port even when host is null, because enrollment never
              goes to the manager traffic port.
            '';
            example = 1515;
            default = 1515;
          };

          caFile = mkOption {
            type = types.nullOr types.path;
            default = null;
            example = "/var/lib/wazuh-certs/root-ca.pem";
            description = ''
              A CA certificate that the manager is verified against during
              enrollment.

              The default is null, which means no verification at all. Without
              a CA the client context keeps the OpenSSL default, which is
              SSL_VERIFY_NONE, because os_auth/ssl.c calls SSL_CTX_set_verify
              only when a CA is supplied. The handshake then completes against
              any certificate, including a self-signed one from an impostor.
              The agent says so at mdebug1, which does not print at the
              default log level.

              Setting this turns verification on for both enrollment paths:
              the agent-auth unit gets -v, and the enrollment that
              wazuh-agentd performs itself gets server_ca_path.

              Verification checks the certificate chain and then matches the
              subject alternative names, and failing that the common name,
              against the address the agent connects to. So the manager's
              certificate must name manager.host, or registration.host when
              that is set. A manager using the certificate it generates for
              itself will not pass.

              The file must be readable by the wazuh user. It is a public
              certificate, so the Nix store is a reasonable place for it.
            '';
          };

          certFile = mkOption {
            type = types.nullOr types.path;
            default = null;
            example = "/var/lib/wazuh-certs/agent.pem";
            description = ''
              A client certificate that this agent presents during enrollment.
              Set it together with keyFile.

              The manager must also be configured for this. authd verifies a
              client certificate only when its own ssl_agent_ca is set.
            '';
          };

          keyFile = mkOption {
            type = types.nullOr types.path;
            default = null;
            example = "/run/secrets/wazuh-agent-key";
            description = ''
              The private key for certFile.

              Use a path outside the Nix store. Anything in the store is world
              readable. The file must be readable by the wazuh user, because
              wazuh-agentd and agent-auth both open it directly. Unlike
              agentAuthPasswordFile nothing copies it, so its own permissions
              are what matter.
            '';
          };
        };
      };
    };

    path = mkOption {
      type = types.listOf types.path;
      default = with pkgs; [
        util-linux
        coreutils-full
        nettools
        procps
      ];
      example = literalExpression "[ pkgs.util-linux pkgs.coreutils-full pkgs.nettools ]";
      description = "Packages to put on the PATH of the Wazuh daemons.";
    };

    syscheck = mkOption {
      description = "File integrity monitoring.";
      default = { };
      type = types.submodule {
        options = {
          directories = mkOption {
            type = types.listOf types.str;
            default = [
              "/etc"
              "/boot"
            ];
            example = literalExpression ''[ "/etc" "/boot" "/root" "/home" ]'';
            description = ''
              Directories to monitor for changes.

              Upstream monitors /etc, /bin, /sbin, /usr/bin, /usr/sbin and
              /boot. On NixOS /sbin and /usr/sbin do not exist, and /bin and
              /usr/bin hold one symlink each, so those four entries monitor
              nothing. The default drops them.

              Do not add /nix/store. It is immutable, every path in it is named
              by a hash of its own contents, and it is large enough to make a
              checksum scan expensive for no gain.

              Adding /run/current-system/sw/bin reports every system rebuild as
              several hundred changes, so add it only if that is what you want.
            '';
          };

          ignore = mkOption {
            type = types.listOf types.str;
            default = [
              "/etc/credstore"
              "/etc/credstore.encrypted"
            ];
            example = literalExpression ''[ "/etc/credstore" "/etc/ssh" ]'';
            description = ''
              Paths to exclude from monitoring, added to the list that upstream
              already ships.

              The default covers the two systemd credential directories. They
              are mode 0700 and owned by root, the daemons run as the wazuh
              user, so each scan of /etc would otherwise log
              "(6922): Cannot open '/etc/credstore': Permission denied".
            '';
          };
        };
      };
    };

    sca = mkOption {
      description = ''
        Security Configuration Assessment.

        The ossec-agent.conf that ships in the package has no sca block, so
        this module never ran before. Upstream writes that block from
        etc/templates/config/generic/sca.template into the ossec.conf that
        install.sh generates, which is a different file.

        SCA is the module that replaces the deprecated rootcheck system_audit
        check. wazuh-syscheckd logs that deprecation on every start.

        Policies come from the package, at ruleset/sca. Upstream installs the
        set that matches the distribution and falls back to
        sca_distro_independent_linux.yml, which is what NixOS gets.
      '';
      default = { };
      type = types.submodule {
        options = {
          enable = mkOption {
            type = types.bool;
            default = true;
            description = "Whether to run configuration assessment scans.";
          };

          scanOnStart = mkOption {
            type = types.bool;
            default = true;
            description = "Whether to scan when the agent starts.";
          };

          interval = mkOption {
            type = types.nonEmptyStr;
            default = "12h";
            example = "1d";
            description = "Time between scans.";
          };

          skipNfs = mkOption {
            type = types.bool;
            default = true;
            description = "Whether to skip NFS mounts during a scan.";
          };
        };
      };
    };

    buffer = mkOption {
      description = ''
        The agent event buffer, which upstream configures as
        client_buffer. Events queue here between the collectors and the
        connection to the manager, so the agent absorbs bursts and
        survives a slow or absent manager. When the queue fills, the
        agent drops new events and tells the manager about the loss.
      '';
      default = { };
      type = types.submodule {
        options = {
          enable = mkOption {
            type = types.bool;
            default = true;
            description = ''
              Whether to buffer events. With the buffer off, the agent
              sends every event directly and loses the flood protection.
              The default matches upstream.
            '';
          };

          queueSize = mkOption {
            type = types.ints.between 1 100000;
            default = 5000;
            example = 20000;
            description = ''
              How many events the queue holds. wazuh-agentd rejects a
              value outside 1 to 100000 and refuses to start
              (src/config/buffer-config.c), so the type carries the same
              bounds and a bad value fails at evaluation instead.
            '';
          };

          eventsPerSecond = mkOption {
            type = types.ints.between 1 1000;
            default = 500;
            example = 250;
            description = ''
              How many buffered events the agent sends per second. The
              same parser accepts 1 to 1000.
            '';
          };
        };
      };
    };

    activeResponse = mkOption {
      description = ''
        Active response, which lets the manager tell this agent to act on a
        finding rather than only report it.

        The default is off, and that is what the sandbox already enforced
        before this option existed. The template ships active response
        enabled, but wazuh-execd runs as the wazuh user with no capabilities,
        and the response that matters, firewall-drop, execs iptables to add
        INPUT and FORWARD DROP rules. So the agent detected and could not
        respond, and nothing said so. Turning this off states that.

        Setting it to true grants wazuh-execd CAP_NET_ADMIN, puts iptables on
        its PATH, and enables the block in ossec.conf. Weigh that against the
        rest of this module: it is the only capability any unit holds.

        Firewall responses are what the grant covers. host-deny writes
        /etc/hosts.deny and disable-account runs passwd, and ProtectSystem =
        "strict" and the absence of root stop both either way.
      '';
      default = { };
      type = types.submodule {
        options = {
          enable = mkOption {
            type = types.bool;
            default = false;
            description = "Whether the agent may act on a finding.";
          };

          capability = mkOption {
            default = { };
            example = {
              route-null.enable = false;
              host-deny.enable = true;
            };
            description = ''
              Which active responses this host is prepared to run. Each one
              adds only what that response needs, so turning one off makes the
              grant smaller. Turn off firewall-drop and route-null and no unit
              in this module holds a capability at all.

              This does not restrict the manager. Every script the package
              ships stays in active-response/bin, and the manager decides
              which to invoke. What these options control is whether the
              binary and the privilege that script needs are present. A
              response the manager sends that is disabled here fails, and the
              failure is written to logs/active-responses.log rather than to
              the journal, so the manager sees it and the agent's own log does
              not.

              disable-account, firewalld-drop, restart-wazuh and the BSD
              firewall scripts have no option here. None of them is blocked by
              a missing capability. See the comment above
              responseRequirements in this file for the reason in each case.
            '';
            type = types.submodule {
              # Generated from responseRequirements, so a response cannot be
              # offered as an option without also declaring what it needs.
              options = mapAttrs (_: req: {
                enable = mkOption {
                  type = types.bool;
                  inherit (req) default description;
                };
              }) responseRequirements;
            };
          };
        };
      };
    };

    config = mkOption {
      type = types.nullOr types.nonEmptyStr;
      default = null;
      description = ''
        Complete contents of ossec.conf. Setting this replaces the generated
        configuration, so it cannot be combined with extraConfig.
      '';
    };

    extraConfig = mkOption {
      type = types.lines;
      default = "";
      description = "Configuration appended to the end of the generated ossec.conf.";
      example = ''
        <!-- The added ossec_config root tag is required -->
        <ossec_config>
          <!-- Extra configuration options as needed -->
        </ossec_config>
      '';
    };

    agentAuthPasswordFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/run/secrets/wazuh-authd-pass";
      description = ''
        Path to a file holding the enrollment password. Use a path outside the
        Nix store. Anything in the store is world readable. The source may be
        readable only by root; systemd passes it to the setup service as a
        credential before that service changes to the wazuh user.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = all (
          name:
          !(hasInfix ''name="${name}"'' configuredXml)
          && !(hasInfix "name='${name}'" configuredXml)
        ) storeUnsafeWodles;
        message = ''
          services.wazuh-agent config enables a wodle that writes a SQLite
          database beside its code. wodles is linked into the read-only Nix
          store, so aws-s3, azure-logs, gcloud-pubsub and docker-listener are
          unsupported until their state paths are moved under /var/ossec/var.
        '';
      }
      {
        assertion = !(cfg.config != null && cfg.extraConfig != "");
        message = ''
          services.wazuh-agent.extraConfig cannot be set when
          services.wazuh-agent.config is set. config replaces the whole file.
        '';
      }
      {
        assertion = (cfg.registration.certFile == null) == (cfg.registration.keyFile == null);
        message = ''
          services.wazuh-agent.registration.certFile and
          services.wazuh-agent.registration.keyFile must be set together. A
          client certificate without its key cannot complete a handshake.
        '';
      }
      {
        assertion = cfg.registration.certFile == null || cfg.registration.caFile != null;
        message = ''
          services.wazuh-agent.registration.certFile is set but
          services.wazuh-agent.registration.caFile is not.

          A client certificate proves this agent to the manager. It does not
          make the agent check the manager, so enrollment would still accept
          any certificate the other side presents. Set caFile as well.
        '';
      }
    ];

    users.users.${wazuhUser} = {
      isSystemUser = true;
      group = wazuhGroup;
      description = "Wazuh agent user";
      home = stateDir;
      # systemd-journal is required to read journald entries.
      extraGroups = [
        "systemd-journal"
        "systemd-network"
      ];
    };

    users.groups.${wazuhGroup} = { };

    warnings = optional execdRunsAsRoot ''
      services.wazuh-agent.activeResponse.capability.disable-account.enable
      is on, so wazuh-execd runs as root with /etc writable.

      No capability reaches this response. shadow reads the real UID, so
      neither a capability nor a setuid wrapper substitutes for root.

      What that costs: execd is the unit that runs whatever the manager tells
      it to run. Every other unit in this module is confined to the wazuh
      user and holds no capability. This one is not. A manager that is
      compromised, or one an attacker can impersonate, reaches root on this
      host through it.

      Enrollment does not verify the manager unless
      services.wazuh-agent.registration.caFile is set. Set it if this is on.
    '';

    security.polkit = mkIf (execdPolkit != "") {
      enable = true;
      extraConfig = execdPolkit;
    };

    systemd.tmpfiles.rules = [
      "d ${stateDir} 0750 root ${wazuhGroup} -"
      "d ${stateDir}/tmp 0750 ${wazuhUser} ${wazuhGroup} 1d"
    ]
    # A selected response may need a file outside /var/ossec to exist and to
    # belong to the wazuh user. Only host-deny does today.
    ++ gather "tmpfiles";

    systemd.targets.multi-user.wants = [ "wazuh.target" ];
    systemd.targets.wazuh.wants = map (d: "${d}.service") daemons;

    systemd.services = listToAttrs (map (d: nameValuePair d (mkService d)) daemons) // {
      wazuh-agent-auth = {
        description = "Enroll the Wazuh agent with its manager";
        after = [
          "setup-pre-wazuh.service"
          "network.target"
          "network-online.target"
        ];
        wants = [
          "setup-pre-wazuh.service"
          "network-online.target"
        ];
        before = map (d: "${d}.service") daemons;
        environment = {
          WAZUH_HOME = stateDir;
        };

        unitConfig = {
          # The marker lives in var, one of the writable state directories.
          # Earlier versions wrote it to the state directory root, which is
          # read-only now, so both paths are honored: the unit is skipped
          # when either exists.
          ConditionPathExists = [
            "!${stateDir}/.agent-registered"
            "!${stateDir}/var/.agent-registered"
          ];
        };

        serviceConfig =
          let
            # Only the host falls back to the manager. The port does not.
            #
            # Enrollment talks to authd, which listens on the registration
            # port, 1515 by default. The manager port, 1514 by default,
            # carries agent data and belongs to remoted, which speaks a
            # different protocol. Sending agent-auth there gets the TCP
            # connection accepted and then dropped, which surfaces as
            # "SSL error (1) ... unexpected eof while reading" and the
            # misleading "Connection refused by the manager".
            host = if cfg.registration.host != null then cfg.registration.host else cfg.manager.host;

            # -v, -x and -k are os_auth/main-client.c:184-200. Without -v the
            # SSL context keeps SSL_VERIFY_NONE, so any certificate passes.
            certFlags = concatStringsSep " " (
              optional (cfg.registration.caFile != null) "-v ${cfg.registration.caFile}"
              ++ optional (cfg.registration.certFile != null) "-x ${cfg.registration.certFile}"
              ++ optional (cfg.registration.keyFile != null) "-k ${cfg.registration.keyFile}"
            );

            # Record the enrollment only when it produced a key. agent-auth
            # can report a failure and still exit 0, and ExecStartPost runs
            # on exit 0, so an unconditional touch marks a failed enrollment
            # as done. ConditionPathExists then skips every later attempt.
            markRegistered = pkgs.writeShellScript "wazuh-mark-registered" ''
              if [ ! -s ${stateDir}/etc/client.keys ]; then
                echo "wazuh-agent-auth: ${stateDir}/etc/client.keys is missing or empty." >&2
                echo "wazuh-agent-auth: enrollment did not complete. Not marking it done." >&2
                exit 1
              fi
              touch ${stateDir}/var/.agent-registered
            '';
          in
          hardening
          // {
            Type = "oneshot";
            User = wazuhUser;
            Group = wazuhGroup;
            # This unit is one of the two that write etc: agent-auth writes
            # etc/client.keys. It writes var too, for the marker above.
            ReadWritePaths = writableStateDirsFor "wazuh-agent-auth";
            NoExecPaths = noExecStateDirsFor "wazuh-agent-auth";
            ExecStart =
              "${pkg}/bin/agent-auth -m ${host} -p ${toString cfg.registration.port}"
              + optionalString (certFlags != "") " ${certFlags}";
            ExecStartPost = "${markRegistered}";
          };
      };

      setup-pre-wazuh = {
        description = "Set up the Wazuh agent directory structure";

        # Pulled in by the target directly, not only by wazuh-agent-auth.
        # Once the agent is enrolled, wazuh-agent-auth is skipped by its
        # ConditionPathExists, and this unit refreshes the package files that
        # every daemon reads, so it must not depend on that unit running.
        wantedBy = [
          "wazuh-agent-auth.service"
          "wazuh.target"
        ];
        before = [ "wazuh-agent-auth.service" ] ++ map (d: "${d}.service") daemons;
        serviceConfig = hardening // {
          Type = "oneshot";
          User = "root";
          Group = "root";
          # Root owns the fixed layout, migrates a tree previously owned by
          # wazuh, and hands mutable state back. These cover traversal,
          # ownership and mode changes; no process or network capability is
          # needed.
          CapabilityBoundingSet = [
            "CAP_CHOWN"
            "CAP_DAC_OVERRIDE"
            "CAP_FOWNER"
          ];
          # This unit manages the fixed layout and reads a credential that
          # PID 1 already resolved. It has no reason to see a network.
          PrivateNetwork = true;

          # This is the root-owned layout and migration unit, so it must
          # write the whole state directory. It gets that through "full"
          # rather than through a ReadWritePaths bind over /var/ossec: on
          # systemd 261, sandbox mounts of units that start together
          # propagate between the namespaces under construction, and a
          # writable /var/ossec bind that lands in a daemon namespace
          # covers the package trees the daemon must not write. "full"
          # keeps /etc and the vendor trees read-only and creates no mount
          # under /var at all, so this unit has nothing to leak. The
          # the script's explicit paths bound what it changes.
          #
          # NoExecPaths must be empty here too, and not only for the leak.
          # On the first boot this unit is what creates the state
          # directories, and a namespace entry that names a directory
          # which does not exist yet fails the unit with status
          # 226/NAMESPACE before one file is copied.
          ProtectSystem = "full";
          ReadWritePaths = [ ];
          NoExecPaths = [ ];
          LoadCredential = optional (cfg.agentAuthPasswordFile != null) (
            "${enrollmentPasswordCredential}:${toString cfg.agentAuthPasswordFile}"
          );
          ExecStart =
            let
              script = pkgs.writeShellApplication {
                name = "wazuh-prestart";
                runtimeInputs = [
                  pkgs.coreutils
                  pkgs.findutils
                ];
                text = preStart;
              };
            in
            "${script}/bin/wazuh-prestart";
        };
      };
    };

    # security.wrappers is deliberately not used here.
    #
    # It built a setuid and setgid wrapper per daemon, owned wazuh:wazuh, at
    # mode -r-s--s--x. The trailing x is world execute, so every local user
    # could run those binaries as the wazuh user, which owns /var/ossec and
    # therefore etc/client.keys, the agent's shared secret with the manager.
    #
    # The wrappers bought nothing in return. systemd already sets User and
    # Group, the privsep patch removed the privilege drop that a wrapper would
    # have served, and the w_homedir patch made the daemons read WAZUH_HOME
    # from the environment rather than resolving /proc/self/exe. ExecStart now
    # names the store path directly, which is how agent-auth has always run.
  };
}
