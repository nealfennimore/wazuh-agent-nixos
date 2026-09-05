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

  # Replace the whole block, not the bare <disabled> line. The template holds
  # five copies of "<disabled>no</disabled>", and substitute rewrites every
  # match, so editing the line alone would also silence four unrelated modules.
  activeResponseBlock = ''
    <active-response>
        <disabled>no</disabled>
      </active-response>'';

  activeResponseReplacement = ''
    <active-response>
        <disabled>${yesNo (!cfg.activeResponse.enable)}</disabled>
      </active-response>'';

  # The agent event buffer. Replace the whole block for the same reason as
  # active-response below: the template holds five copies of
  # "<disabled>no</disabled>", so the line alone is not a safe anchor. The
  # upstream comment line inside the block does not survive; the option
  # descriptions carry that information now.
  clientBufferBlock = ''
    <client_buffer>
        <!-- Agent buffer options -->
        <disabled>no</disabled>
        <queue_size>5000</queue_size>
        <events_per_second>500</events_per_second>
      </client_buffer>'';

  clientBufferReplacement = ''
    <client_buffer>
        <disabled>${yesNo (!cfg.buffer.enable)}</disabled>
        <queue_size>${toString cfg.buffer.queueSize}</queue_size>
        <events_per_second>${toString cfg.buffer.eventsPerSecond}</events_per_second>
      </client_buffer>'';

  # The template gives <server> an address and no port.
  serverAddress = "<address>IP</address>";
  serverAddressAndPort = ''
    <address>${cfg.manager.host}</address>
          <port>${toString cfg.manager.port}</port>'';

  # Settings for the enrollment that wazuh-agentd performs itself, which is
  # a different code path from the agent-auth unit and the one that runs on
  # every boot. Both paths need the same identity and the same certificate
  # files. Configuring only agent-auth would leave the daemon enrolling
  # unverified, under the hostname and without groups.
  #
  # Element names are config/client-config.c:387-393. The block goes inside
  # <client>, so anchor on the one </server> in the template.
  enrollmentSettings =
    lib.optional (
      cfg.registration.agentName != null
    ) "<agent_name>${cfg.registration.agentName}</agent_name>"
    ++ lib.optional (
      cfg.registration.groups != [ ]
    ) "<groups>${lib.concatStringsSep "," cfg.registration.groups}</groups>"
    ++ lib.optional (
      cfg.registration.caFile != null
    ) "<server_ca_path>${cfg.registration.caFile}</server_ca_path>"
    ++ lib.optional (
      cfg.registration.certFile != null
    ) "<agent_certificate_path>${cfg.registration.certFile}</agent_certificate_path>"
    ++ lib.optional (
      cfg.registration.keyFile != null
    ) "<agent_key_path>${cfg.registration.keyFile}</agent_key_path>";

  serverClose = "</server>";

  # Replacing </server> with itself when nothing is configured keeps the
  # --replace-fail below unconditional, so the pattern is still checked.
  serverCloseAndEnrollment =
    if enrollmentSettings == [ ] then
      serverClose
    else
      ''
        </server>
            <enrollment>
              ${lib.concatStringsSep "\n          " enrollmentSettings}
            </enrollment>'';

  yesNo = b: if b then "yes" else "no";

  # ossec-agent.conf ships no <sca> block, so the module never ran here.
  # install.sh writes one into the ossec.conf that it generates, from
  # etc/templates/config/generic/sca.template, but this file builds from
  # ossec-agent.conf instead. These are that template's five elements, with
  # the values behind options.
  #
  # No <policies> element. wmodules-sca.c:104 loads every policy in
  # ruleset/sca when none is named, and preStart copies that directory.
  #
  # The block is always written, and <enabled> carries the decision. Leaving
  # it out would fall back to whatever the module compiles in, which is not
  # something this module can state.
  scaSection = ''
    <ossec_config>
      <sca>
        <enabled>${yesNo cfg.sca.enable}</enabled>
        <scan_on_start>${yesNo cfg.sca.scanOnStart}</scan_on_start>
        <interval>${cfg.sca.interval}</interval>
        <skip_nfs>${yesNo cfg.sca.skipNfs}</skip_nfs>
      </sca>
    </ossec_config>
  '';

  # ossec-agent.conf ships no <labels> block either, so it appends like sca.
  # Only wazuh-agentd reads it (src/client-agent/config.c:68), and a label
  # error there is fatal before enrollment starts.
  #
  # Keys and values are written verbatim, not XML-escaped. Wazuh's own
  # parser (src/os_xml) never decodes entities: it stores content byte for
  # byte, so a raw "&" is both accepted and correct, while an escaped
  # "&amp;" would reach the manager as the literal five characters. The few
  # characters the parser genuinely cannot carry are rejected at evaluation
  # in default.nix, as are keys starting with "_", which labels-config.c:52
  # only warns about and skips.
  #
  # The section is written only when labels exist. An empty <labels> block
  # would read as configured.
  #
  # Double-quoted strings on purpose. An indented string strips leading
  # whitespace even on a single line, so '' hidden="yes"'' loses the space
  # that separates it from the key attribute. Wazuh's own XML parser then
  # rejects the whole file with "Bad attribute closing", and every daemon
  # exits at its first log call, because os_logging_config reads this file
  # too and clears the parse error before it reports it.
  labelLine =
    key: label:
    "<label key=\"${key}\""
    + lib.optionalString label.hidden " hidden=\"yes\""
    + ">${label.value}</label>";

  labelsSection = lib.optionalString (cfg.labels != { }) ''
    <ossec_config>
      <labels>
        ${lib.concatStringsSep "\n    " (lib.mapAttrsToList labelLine cfg.labels)}
      </labels>
    </ossec_config>
  '';

  # The <logging> section, also absent from ossec-agent.conf. Each daemon
  # reads it on its own, through os_logging_config in shared/debug_op.c: an
  # absent or empty log_format falls back to plain silently, and an unknown
  # value is fatal. The block is always written, so the file states the
  # choice instead of leaning on the fallback. An assertion in default.nix
  # keeps at least one format on, so logFormat is never empty here.
  logFormat = lib.concatStringsSep "," (
    lib.optional cfg.logging.plain "plain" ++ lib.optional cfg.logging.json "json"
  );

  loggingSection = ''
    <ossec_config>
      <logging>
        <log_format>${logFormat}</log_format>
      </logging>
    </ossec_config>
  '';
in
pkgs.runCommand "ossec.conf"
  {
    inherit (cfg) extraConfig;
    inherit scaSection labelsSection loggingSection;
    passAsFile = [
      "extraConfig"
      "scaSection"
      "labelsSection"
      "loggingSection"
    ];
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
                     ${lib.escapeShellArg ignoreLines} \
      --replace-fail ${lib.escapeShellArg activeResponseBlock} \
                     ${lib.escapeShellArg activeResponseReplacement} \
      --replace-fail ${lib.escapeShellArg clientBufferBlock} \
                     ${lib.escapeShellArg clientBufferReplacement} \
      --replace-fail ${lib.escapeShellArg serverClose} \
                     ${lib.escapeShellArg serverCloseAndEnrollment}

    # The active response reader must survive as a plain file reader.
    grep -q '<location>/var/ossec/logs/active-responses.log</location>' ossec.conf
    test "$(grep -c '<log_format>journald</log_format>' ossec.conf)" -eq 1

    # Exactly one active-response block, carrying the value this module chose.
    # Four other modules use the same <disabled> spelling, so a substitution
    # that caught the wrong one would be invisible here without the count.
    test "$(grep -c '<active-response>' ossec.conf)" -eq 1
    grep -A1 '<active-response>' ossec.conf \
      | grep -q '<disabled>${yesNo (!cfg.activeResponse.enable)}</disabled>'

    # Exactly one buffer block, carrying the values the options chose.
    test "$(grep -c '<client_buffer>' ossec.conf)" -eq 1
    grep -q '<queue_size>${toString cfg.buffer.queueSize}</queue_size>' ossec.conf
    grep -q '<events_per_second>${toString cfg.buffer.eventsPerSecond}</events_per_second>' ossec.conf
    grep -A1 '<client_buffer>' ossec.conf \
      | grep -q '<disabled>${yesNo (!cfg.buffer.enable)}</disabled>'

    # Enrollment settings are opt in, so assert both directions. An empty
    # <enrollment> block would be worse than none: it reads as configured.
    test "$(grep -c '<enrollment>' ossec.conf)" -eq ${if enrollmentSettings == [ ] then "0" else "1"}
    ${lib.optionalString (cfg.registration.agentName != null) ''
      grep -qF '<agent_name>${cfg.registration.agentName}</agent_name>' ossec.conf
    ''}
    ${lib.optionalString (cfg.registration.groups != [ ]) ''
      grep -qF '<groups>${lib.concatStringsSep "," cfg.registration.groups}</groups>' ossec.conf
    ''}

    # No FHS binary directory may survive the replacement above.
    if grep -qE '<directories>[^<]*/(usr/)?s?bin' ossec.conf; then
      echo "generate-agent-config: an FHS binary directory survived the" >&2
      echo "substitution. NixOS does not have these paths. Rework the edit." >&2
      exit 1
    fi

    # The template must not already carry an sca block, or the agent would get
    # two and the second would win silently.
    if grep -q '<sca>' ossec.conf; then
      echo "generate-agent-config: the template now ships its own <sca> block." >&2
      echo "Drop scaSection here rather than append a second one." >&2
      exit 1
    fi

    # Same rule for the other appended sections. For logging the failure
    # mode is sharper: os_logging_config reads the first log_format it
    # finds, so a template copy would silently win over the options.
    if grep -q '<labels>' ossec.conf; then
      echo "generate-agent-config: the template now ships its own <labels> block." >&2
      echo "Merge the labels options into it rather than append a second one." >&2
      exit 1
    fi
    if grep -q '<logging>' ossec.conf; then
      echo "generate-agent-config: the template now ships its own <logging> block." >&2
      echo "Substitute it rather than append a second one; the first wins." >&2
      exit 1
    fi

    # Wazuh accepts more than one ossec_config root tag, so all of these
    # append as their own root.
    cat ossec.conf "$scaSectionPath" "$labelsSectionPath" "$loggingSectionPath" \
      "$extraConfigPath" > $out

    # No XML validator runs here on purpose. Wazuh's parser accepts input
    # that a real XML parser rejects, a raw ampersand above all, and treats
    # entities as literal bytes. A well-formedness check would therefore
    # fail configurations the daemons accept, and pass escaping the daemons
    # deliver corrupted. checks.agent boots the daemons against the file,
    # and their parser is the only arbiter that counts.
  ''
