{
  description = "Wazuh agent package and NixOS module";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      ...
    }:
    let
      # The package is Linux only. Evaluating it for Darwin serves no purpose and
      # makes `nix flake check` report failures nobody can act on.
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      wazuhModule =
        {
          lib,
          pkgs,
          ...
        }:
        {
          imports = [ ./nixos/wazuh-agent ];

          # Supply the package here so that the module works on its own. Without
          # this line the consumer must also apply overlays.default, or evaluation
          # fails with "attribute 'wazuh-agent' missing". mkDefault keeps
          # services.wazuh-agent.package overridable.
          services.wazuh-agent.package = lib.mkDefault (pkgs.callPackage ./pkgs/wazuh-agent.nix { });
        };
      # The throwaway test VM. examples/vm.nix imports qemu-vm.nix itself, so
      # this list evaluates both as a plain NixOS system and as a VM.
      vmModules = [
        wazuhModule
        ./examples/vm.nix
      ];
    in
    {
      overlays.default = final: _prev: {
        wazuh-agent = final.callPackage ./pkgs/wazuh-agent.nix { };
      };

      nixosModules.wazuh-agent = wazuhModule;
      nixosModules.default = wazuhModule;

      # For `nixos-rebuild build-vm --flake .#wazuh-agent-vm`.
      nixosConfigurations.wazuh-agent-vm = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = vmModules;
      };
    }
    // flake-utils.lib.eachSystem supportedSystems (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        formatter = pkgs.alejandra;
        packages.wazuh-agent = pkgs.callPackage ./pkgs/wazuh-agent.nix { };
        packages.default = pkgs.callPackage ./pkgs/wazuh-agent.nix { };

        # A bootable QEMU image with the agent enabled:
        #   nix build .#vm && ./result/bin/run-wazuh-agent-vm
        packages.vm =
          (nixpkgs.lib.nixosSystem {
            inherit system;
            modules = vmModules;
          }).config.system.build.vm;

        # A headless test of the module. It asserts activation and the
        # generated ossec.conf. It does not assert enrollment, which needs a
        # manager this repository does not package.
        checks.agent = import ./nixos/tests/agent.nix {
          inherit pkgs wazuhModule;
        };

        # `.envrc` runs `use flake`. Without this shell, direnv falls back to
        # the build environment of packages.default, which pulls the whole
        # dependency closure to open a prompt.
        devShells.default = pkgs.mkShellNoCC {
          packages = [
            pkgs.nixfmt
            pkgs.curl
            pkgs.gitMinimal
          ];
        };
      }
    );
}
