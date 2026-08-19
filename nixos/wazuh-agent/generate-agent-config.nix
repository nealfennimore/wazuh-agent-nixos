# Build ossec.conf from the ossec-agent.conf that ships in the package output.
#
# This runs at build time, not at evaluation time. The previous version called
# builtins.fetchurl with a hash pinned to the package version, which had to be
# updated by hand on every bump.
#
# TODO: replace the string substitution with a real XML writer.
{
  cfg,
  pkgs,
}:
let
  inherit (pkgs) lib;

  # Every pattern below starts at column 0. A Nix indented string strips the
  # smallest indentation it finds, so starting at column 0 strips nothing and
  # the inner two and four space indents survive exactly as upstream writes
  # them. substitute matches literally, so the whitespace has to be right.

  # Upstream collects three syslog files. NixOS creates none of them, because
  # it logs to journald.
  #
  # The previous version replaced the bare string
  # "<log_format>syslog</log_format>", but substitute rewrites every match and
  # the template holds four of them. That turned the active response reader and
  # both other file readers into journald readers pointed at file paths, which
  # is not a combination Wazuh accepts. Replace the three file readers as one
  # block instead, and leave the active response reader alone.
  syslogFileReaders = ''
    <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/messages</location>
      </localfile>

      <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/auth.log</location>
      </localfile>

      <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/syslog</location>
      </localfile>'';

  journaldReader = ''
    <localfile>
        <log_format>journald</log_format>
        <location>journald</location>
      </localfile>'';

  # Upstream watches the FHS binary directories. On NixOS /sbin and /usr/sbin
  # do not exist at all, and /bin and /usr/bin hold one symlink each, sh and
  # env. So four of the six entries monitor nothing, and the remaining coverage
  # is not what the operator thinks it is.
  #
  # Nothing is lost by dropping them. Every binary on NixOS lives in /nix/store
  # under a path that is a hash of its own contents, so the store already gives
  # a stronger guarantee than a periodic checksum. What is worth watching is the
  # mutable surface, which syscheck.directories names.
  upstreamDirectories = ''
    <directories>/etc,/usr/bin,/usr/sbin</directories>
        <directories>/bin,/sbin,/boot</directories>'';

  directoriesLine =
    if cfg.syscheck.directories == [ ] then
      "<!-- services.wazuh-agent.syscheck.directories is empty -->"
    else
      "<directories>${lib.concatStringsSep "," cfg.syscheck.directories}</directories>";

  # systemd creates /etc/credstore and /etc/credstore.encrypted as 0700 root,
  # and the daemons run as the wazuh user, so every scan of /etc logs
  # "(6922): Cannot open '/etc/credstore': Permission denied". The agent cannot
  # read them and never will, so ignore them instead of logging twice a day.
  lastUpstreamIgnore = "<ignore>/sys/kernel/debug</ignore>";
  ignoreLines = lib.concatStringsSep "\n    " (
    [ lastUpstreamIgnore ] ++ map (p: "<ignore>${p}</ignore>") cfg.syscheck.ignore
  );

  # The template gives <server> an address and no port.
  serverAddress = "<address>IP</address>";
  serverAddressAndPort = ''
    <address>${cfg.manager.host}</address>
          <port>${toString cfg.manager.port}</port>'';
in
pkgs.runCommand "ossec.conf"
  {
    inherit (cfg) extraConfig;
    passAsFile = [ "extraConfig" ];
    template = "${cfg.package}/share/wazuh-agent/ossec-agent.conf";
  }
  ''
    substitute "$template" ossec.conf \
      --replace-fail ${lib.escapeShellArg serverAddress} \
                     ${lib.escapeShellArg serverAddressAndPort} \
      --replace-fail ${lib.escapeShellArg syslogFileReaders} \
                     ${lib.escapeShellArg journaldReader} \
      --replace-fail ${lib.escapeShellArg upstreamDirectories} \
                     ${lib.escapeShellArg directoriesLine} \
      --replace-fail ${lib.escapeShellArg lastUpstreamIgnore} \
                     ${lib.escapeShellArg ignoreLines}

    # The active response reader must survive as a plain file reader.
    grep -q '<location>/var/ossec/logs/active-responses.log</location>' ossec.conf
    test "$(grep -c '<log_format>journald</log_format>' ossec.conf)" -eq 1

    # No FHS binary directory may survive the replacement above.
    if grep -qE '<directories>[^<]*/(usr/)?s?bin' ossec.conf; then
      echo "generate-agent-config: an FHS binary directory survived the" >&2
      echo "substitution. NixOS does not have these paths. Rework the edit." >&2
      exit 1
    fi

    # Wazuh accepts more than one ossec_config root tag, so extraConfig appends.
    cat ossec.conf "$extraConfigPath" > $out
  ''
