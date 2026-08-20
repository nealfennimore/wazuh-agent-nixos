# A NixOS test node that runs the Wazuh manager in a container.
#
# Scope: enough manager to accept an enrollment, to accept an agent connection,
# and to write the agent's events to its archive. That is what the agent module
# needs to prove. Nothing here is a production manager.
#
# The indexer and the dashboard are deliberately absent. The check never reads
# an index, the two images together are several times the size of this one, and
# the indexer needs a TLS certificate set that this repository does not hold.
# Nothing in the manager image waits for them: cont-init.d/1-config-filebeat
# only rewrites filebeat.yml, so filebeat retries a publish that never succeeds
# and the manager daemons come up regardless.
#
# This file uses qemu-vm options, so it belongs to a test node and not to a
# real host.
{ pkgs, ... }:
let
  managerImage = pkgs.callPackage ./wazuh-manager-image.nix { };
in
{
  # The manager runs a full Wazuh install plus filebeat, and the image unpacks
  # to several gigabytes. The test defaults are far too small for both.
  virtualisation.memorySize = 4096;
  virtualisation.diskSize = 16384;

  # The test network is closed and has one agent on it. A firewall here only
  # adds a way for the check to fail for a reason that is not about Wazuh.
  networking.firewall.enable = false;

  virtualisation.oci-containers = {
    backend = "docker";
    containers.wazuh-manager = {
      image = managerImage.tag;
      imageFile = managerImage.image;
      autoStart = true;

      # Host networking, so the container binds this node's own interface and
      # the agent reaches 1514 and 1515 at the node address.
      #
      # Do not add `ports` alongside this. Docker discards published ports
      # under host networking, so a port list here reads as configuration that
      # does nothing.
      #
      # The manager opens a file descriptor per agent connection and locks its
      # decoder memory. Both ulimits come from the upstream compose file.
      extraOptions = [
        "--network=host"
        "--ulimit"
        "nofile=655360:655360"
        "--ulimit"
        "memlock=-1:-1"
      ];
    };
  };
}
