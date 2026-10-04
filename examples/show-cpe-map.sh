#!/usr/bin/env bash
# Shows where the CPE vendors for the Nix package inventory come from.
#
# The NixOS module builds a JSON map from nixpkgs pname to CPE vendor and
# product, and the agent attaches those to every package row it reports. The
# manager rejects an NVD candidate whose vendor the package does not carry, so
# this map decides which Nix packages can match the NVD at all.
#
# With no argument, the script evaluates nixos/wazuh-agent/cpe-map.nix against
# the nixpkgs that flake.lock pins and prints:
#
#   counts      how many entries each layer supplied
#   source      for each pname, which layer won
#   unresolved  packages that no layer knows a vendor for
#   map         the file the wazuh-nix-inventory unit writes
#
# With package attribute names as arguments, it prints the raw
# meta.identifiers of each one instead, so you can see what nixpkgs itself
# says before any fallback applies:
#
#   ./examples/show-cpe-map.sh glibc openssl linux-pam
#
# Nothing builds. Evaluating meta is all this does.
set -euo pipefail

cd "$(dirname "$0")/.."

# jq pretty-prints when present. nix eval --json is one line otherwise.
pretty() {
  if command -v jq > /dev/null; then
    jq .
  else
    cat
  fi
}

# The locked nixpkgs of this flake, for the running system.
pkgs='
  let
    flake = builtins.getFlake (toString ./.);
  in
  flake.inputs.nixpkgs.legacyPackages.${builtins.currentSystem}
'

if [ "$#" -eq 0 ]; then
  nix eval --json --impure --expr "
    let
      pkgs = $pkgs;
      cpe = import ./nixos/wazuh-agent/cpe-map.nix;
    in
    cpe.report { inherit (pkgs) lib; inherit pkgs; }
  " | pretty
  exit 0
fi

for attr in "$@"; do
  echo "== $attr"
  nix eval --json --impure --expr "
    let
      pkgs = $pkgs;
      drv = pkgs.lib.attrByPath (pkgs.lib.splitString \".\" \"$attr\") null pkgs;
    in
    if drv == null then
      \"no such attribute\"
    else
      {
        pname = drv.pname or null;
        version = drv.version or null;
        identifiers = drv.meta.identifiers or \"no meta.identifiers in this nixpkgs\";
      }
  " | pretty
done
