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
  }: let
    # The package is Linux only. Evaluating it for Darwin serves no purpose and
    # makes `nix flake check` report failures nobody can act on.
    supportedSystems = ["x86_64-linux" "aarch64-linux"];

    wazuhModule = {
      lib,
      pkgs,
      ...
    }: {
      imports = [./nixos/wazuh-agent];

      # Supply the package here so that the module works on its own. Without
      # this line the consumer must also apply overlays.default, or evaluation
      # fails with "attribute 'wazuh-agent' missing". mkDefault keeps
      # services.wazuh-agent.package overridable.
      services.wazuh-agent.package =
        lib.mkDefault (pkgs.callPackage ./pkgs/wazuh-agent.nix {});
    };
  in
    {
      overlays.default = final: _prev: {
        wazuh-agent = final.callPackage ./pkgs/wazuh-agent.nix {};
      };

      nixosModules.wazuh-agent = wazuhModule;
      nixosModules.default = wazuhModule;
    }
    // flake-utils.lib.eachSystem supportedSystems (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        formatter = pkgs.alejandra;
        packages.wazuh-agent = pkgs.callPackage ./pkgs/wazuh-agent.nix {};
        packages.default = pkgs.callPackage ./pkgs/wazuh-agent.nix {};

        # `.envrc` runs `use flake`. Without this shell, direnv falls back to
        # the build environment of packages.default, which pulls the whole
        # dependency closure to open a prompt.
        devShells.default = pkgs.mkShellNoCC {
          packages = [
            pkgs.alejandra
            pkgs.curl
            pkgs.gitMinimal
          ];
        };
      }
    );
}
