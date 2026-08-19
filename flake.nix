{
  description = "Wazuh agent package and NixOS module";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    nixpkgs,
    flake-utils,
    ...
  }:
    {
      overlays.default = final: _prev: {
        wazuh-agent = final.callPackage ./pkgs/wazuh-agent.nix {};
      };

      nixosModules.wazuh-agent = import ./nixos/wazuh-agent;
      nixosModules.default = import ./nixos/wazuh-agent;
    }
    // flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        formatter = pkgs.alejandra;
        packages.wazuh-agent = pkgs.callPackage ./pkgs/wazuh-agent.nix {};
        packages.default = pkgs.callPackage ./pkgs/wazuh-agent.nix {};
      }
    );
}
