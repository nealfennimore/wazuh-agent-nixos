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
}: let
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

  # The template gives <server> an address and no port.
  serverAddress = "<address>IP</address>";
  serverAddressAndPort = ''
<address>${cfg.manager.host}</address>
      <port>${toString cfg.manager.port}</port>'';
in
  pkgs.runCommand "ossec.conf" {
    inherit (cfg) extraConfig;
    passAsFile = ["extraConfig"];
    template = "${cfg.package}/share/wazuh-agent/ossec-agent.conf";
  } ''
    substitute "$template" ossec.conf \
      --replace-fail ${lib.escapeShellArg serverAddress} \
                     ${lib.escapeShellArg serverAddressAndPort} \
      --replace-fail ${lib.escapeShellArg syslogFileReaders} \
                     ${lib.escapeShellArg journaldReader}

    # The active response reader must survive as a plain file reader.
    grep -q '<location>/var/ossec/logs/active-responses.log</location>' ossec.conf
    test "$(grep -c '<log_format>journald</log_format>' ossec.conf)" -eq 1

    # Wazuh accepts more than one ossec_config root tag, so extraConfig appends.
    cat ossec.conf "$extraConfigPath" > $out
  ''
