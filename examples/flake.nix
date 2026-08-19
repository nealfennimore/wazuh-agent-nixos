# A complete consumer flake. Change the hostname, the system, and the manager
# address, then run:
#
#   sudo nixos-rebuild switch --flake .#nixos-agent-01
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    wazuh-agent.url = "git+https://github.com/nealfennimore/wazuh-agent-nixos";
  };

  outputs =
    {
      nixpkgs,
      wazuh-agent,
      ...
    }:
    {
      nixosConfigurations.nixos-agent-01 = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          # The module carries its own package. The overlay is not required.
          wazuh-agent.nixosModules.wazuh-agent
          ./configuration.nix
          ./hardware-configuration.nix
        ];
      };
    };
}
