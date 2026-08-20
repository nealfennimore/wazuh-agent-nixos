# The Wazuh manager container image, pinned by a checked-in JSON file.
#
# This repository packages the agent. The manager exists here only to give the
# enrollment test something to enroll against, so it comes from Docker Hub
# rather than from source.
#
# The pin is wazuh-manager-image.<arch>.json, written by
# prefetch-manager-image.sh and committed. Nothing in this file is edited by
# hand.
#
# Keep `version` in step with `version` in pkgs/wazuh-agent.nix. Wazuh supports
# an agent older than its manager. It does not support an agent newer than its
# manager, so a stale pin fails in a way that looks like a module bug. The
# check below compares the two rather than trust them to match.
{
  dockerTools,
  lib,
  go,
}:
let
  version = "4.14.7";
  imageName = "wazuh/wazuh-manager";

  # dockerTools.pullImage defaults its `arch` to go.GOARCH, so the pin must be
  # keyed the same way. One file per architecture, because one prefetch run
  # produces one image.
  arch = go.GOARCH;

  pinName = "wazuh-manager-image.${arch}.json";
  pinFile = ./. + "/${pinName}";
  havePin = builtins.pathExists pinFile;
  pin = builtins.fromJSON (builtins.readFile pinFile);

  regenerate = "./nixos/tests/prefetch-manager-image.sh ${version} ${arch}";

  # Read through `or null` so that a truncated or hand-edited file reports the
  # mismatch rather than an attribute error.
  problem =
    if !havePin then
      ''
        nixos/tests/wazuh-manager-image.nix has no pin for ${arch}.

        The enrollment check needs the ${imageName}:${version} image from
        Docker Hub. Nix cannot fetch it without a manifest digest and a hash,
        and neither value can be guessed.

        Run this on a host that reaches registry-1.docker.io, then commit the
        file it writes:

          ${regenerate}

        This affects checks.enrollment only. checks.agent needs no manager and
        still runs.
      ''
    else if (pin.imageName or null) != imageName then
      ''
        nixos/tests/${pinName} pins ${pin.imageName or "nothing"},
        but this file expects ${imageName}. Regenerate the pin:

          ${regenerate}
      ''
    else if (pin.finalImageTag or null) != version then
      ''
        nixos/tests/${pinName} pins ${imageName}:${pin.finalImageTag or "nothing"},
        but this file expects ${version}.

        An agent newer than its manager is not a supported combination, so a
        stale pin fails during the test rather than here. Regenerate it:

          ${regenerate}
      ''
    else
      null;
in
lib.throwIf (problem != null) problem {
  inherit version;

  # dockerTools.pullImage writes a tarball. virtualisation.oci-containers
  # loads it and then runs the tag, so the two must agree.
  tag = "${pin.finalImageName}:${pin.finalImageTag}";

  # These five names are exactly what `nix-prefetch-docker --json` writes.
  # Naming them rather than passing the whole set keeps a missing key an
  # error here instead of a surprise inside pullImage.
  image = dockerTools.pullImage {
    inherit (pin)
      imageName
      imageDigest
      finalImageName
      finalImageTag
      hash
      ;
  };
}
