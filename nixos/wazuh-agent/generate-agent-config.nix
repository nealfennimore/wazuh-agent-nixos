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
pkgs.runCommand "ossec.conf" {
  inherit (cfg) extraConfig;
  passAsFile = ["extraConfig"];
  template = "${cfg.package}/share/wazuh-agent/ossec-agent.conf";
} ''
  substitute "$template" ossec.conf \
    --replace-fail \
      '<address>IP</address>' \
      '<address>${cfg.manager.host}</address><port>${toString cfg.manager.port}</port>' \
    --replace-fail \
      '<log_format>syslog</log_format>' \
      '<log_format>journald</log_format>' \
    --replace-fail \
      '<location>/var/log/syslog</location>' \
      '<location>journald</location>'

  # Wazuh accepts more than one ossec_config root tag, so extraConfig appends.
  cat ossec.conf "$extraConfigPath" > $out
''
