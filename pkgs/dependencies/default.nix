{
  dependencyVersion,
  fetchurl,
  lib,
  ...
}: let
  fetcher = {
    name,
    sha256,
  }:
    fetchurl {
      url = "https://packages.wazuh.com/deps/${dependencyVersion}/libraries/sources/${name}.tar.gz";
      inherit sha256;
    };
in
  lib.mapAttrsToList (_name: dep: fetcher {inherit (dep) name sha256;}) (
    import ./external_dependencies.nix
  )
