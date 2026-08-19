# An example NixOS configuration for the Wazuh agent.
#
# Copy the services.wazuh-agent block into a host configuration. Import the
# module first. See examples/flake.nix for a complete flake.
{...}: {
  services.wazuh-agent = {
    enable = true;

    # The Wazuh manager. Required. Use an address the host can reach.
    manager.host = "192.168.1.2";
    manager.port = 1514;

    # A separate enrollment server. Leave this out when the manager also
    # handles enrollment.
    # registration.host = "192.168.1.2";
    # registration.port = 1515;

    # The enrollment password.
    #
    # Write this value as a quoted string, not as a bare path. A bare path
    # such as /run/secrets/wazuh-authd-pass is a Nix path literal, and Nix
    # copies a path literal into the store. The store is world readable.
    #
    # agentAuthPasswordFile = "/run/secrets/wazuh-authd-pass";

    # Configuration appended to the generated ossec.conf. Wazuh accepts more
    # than one ossec_config root tag.
    extraConfig = ''
      <ossec_config>
        <localfile>
          <log_format>syslog</log_format>
          <location>/var/log/nginx/access.log</location>
        </localfile>
      </ossec_config>
    '';
  };

  # The agent reports the hostname to the manager. Set it before enrollment.
  networking.hostName = "nixos-agent-01";
}
