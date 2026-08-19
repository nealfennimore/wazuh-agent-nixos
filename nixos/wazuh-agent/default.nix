{
  config,
  lib,
  pkgs,
  ...
}:
with lib; let
  wazuhUser = "wazuh";
  wazuhGroup = wazuhUser;
  stateDir = "/var/ossec";
  cfg = config.services.wazuh-agent;
  pkg = cfg.package;

  generatedConfig =
    if cfg.config != null
    then pkgs.writeText "ossec.conf" cfg.config
    else import ./generate-agent-config.nix {inherit cfg pkgs;};

  preStart = ''
    ${
      concatMapStringsSep "\n"
      (
        dir: "[ -d ${stateDir}/${dir} ] || cp -Rv --no-preserve=ownership ${pkg}/${dir} ${stateDir}/${dir}"
      )
      [
        "active-response"
        "agentless"
        "bin"
        "etc"
        "lib"
        "logs"
        "queue"
        "tmp"
        "var"
        "wodles"
      ]
    }

    chown -R ${wazuhUser}:${wazuhGroup} ${stateDir}

    find ${stateDir} -type d -exec chmod 770 {} \;
    find ${stateDir} -type f -exec chmod 750 {} \;

    cp ${generatedConfig} ${stateDir}/etc/ossec.conf

    ${optionalString (cfg.agentAuthPasswordFile != null) ''
      install -m 0640 ${cfg.agentAuthPasswordFile} ${stateDir}/etc/authd.pass
    ''}
  '';

  daemons = [
    "wazuh-modulesd"
    "wazuh-logcollector"
    "wazuh-syscheckd"
    "wazuh-agentd"
    "wazuh-execd"
  ];

  mkService = d: {
    description = d;
    wants = ["wazuh-agent-auth.service"];

    partOf = ["wazuh.target"];
    path =
      cfg.path
      ++ [
        "/run/current-system/sw/bin"
        "/run/wrappers/bin"
      ];
    environment = {
      WAZUH_HOME = stateDir;
    };

    serviceConfig = {
      Type = "exec";
      User = wazuhUser;
      Group = wazuhGroup;
      WorkingDirectory = "${stateDir}/";
      CapabilityBoundingSet = ["CAP_SETGID"];

      ExecStart =
        if d != "wazuh-modulesd"
        then "/run/wrappers/bin/${d} -f -c ${stateDir}/etc/ossec.conf"
        else "/run/wrappers/bin/${d} -f";
    };
  };
in {
  options.services.wazuh-agent = {
    enable = mkEnableOption "Wazuh agent";

    package = mkPackageOption pkgs "wazuh-agent" {};

    manager = mkOption {
      description = "The Wazuh manager this agent reports to.";
      type = types.submodule {
        freeformType = with types; attrsOf (oneOf [nonEmptyStr port]);
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
      default = {};
      type = types.submodule {
        freeformType = with types; attrsOf (oneOf [nonEmptyStr port]);
        options = {
          host = mkOption {
            type = types.nullOr types.nonEmptyStr;
            description = "The IP address or hostname of the registration server.";
            example = "192.168.1.2";
            default = null;
          };
          port = mkOption {
            type = types.port;
            description = "The port the registration server listens on.";
            example = 1515;
            default = 1515;
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
        Nix store. Anything in the store is world readable.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = !(cfg.config != null && cfg.extraConfig != "");
        message = ''
          services.wazuh-agent.extraConfig cannot be set when
          services.wazuh-agent.config is set. config replaces the whole file.
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

    users.groups.${wazuhGroup} = {};

    systemd.tmpfiles.rules = [
      "d ${stateDir} 0750 ${wazuhUser} ${wazuhGroup} -"
      "d ${stateDir}/tmp 0750 ${wazuhUser} ${wazuhGroup} 1d"
    ];

    systemd.targets.multi-user.wants = ["wazuh.target"];
    systemd.targets.wazuh.wants = map (d: "${d}.service") daemons;

    systemd.services =
      listToAttrs (map (d: nameValuePair d (mkService d)) daemons)
      // {
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
            ConditionPathExists = "!${stateDir}/.agent-registered";
          };

          serviceConfig = let
            useRegistration = cfg.registration.host != null;
            host =
              if useRegistration
              then cfg.registration.host
              else cfg.manager.host;
            port =
              if useRegistration
              then cfg.registration.port
              else cfg.manager.port;
          in {
            Type = "oneshot";
            User = wazuhUser;
            Group = wazuhGroup;
            ExecStart = "${pkg}/bin/agent-auth -m ${host} -p ${toString port}";
            ExecStartPost = "${pkgs.coreutils}/bin/touch ${stateDir}/.agent-registered";
          };
        };

        setup-pre-wazuh = {
          description = "Set up the Wazuh agent directory structure";
          wantedBy = ["wazuh-agent-auth.service"];
          before = ["wazuh-agent-auth.service"];
          serviceConfig = {
            Type = "oneshot";
            User = wazuhUser;
            Group = wazuhGroup;
            ExecStart = let
              script = pkgs.writeShellApplication {
                name = "wazuh-prestart";
                runtimeInputs = [pkgs.coreutils pkgs.findutils];
                text = preStart;
              };
            in "${script}/bin/wazuh-prestart";
          };
        };
      };

    # TODO: narrow this. The daemons already run as the wazuh user, so setuid
    # and setgid to that same user buys little. Confirm against a running agent
    # before changing it.
    security.wrappers = listToAttrs (
      map (
        d:
          nameValuePair d {
            setgid = true;
            setuid = true;
            owner = wazuhUser;
            group = wazuhGroup;
            source = "${pkg}/bin/${d}";
          }
      )
      daemons
    );
  };
}
