# The Wazuh manager container image, pinned by manifest digest.
#
# This repository packages the agent. The manager exists here only to give the
# enrollment test something to enroll against, so it comes from Docker Hub
# rather than from source.
#
# Keep `version` in step with `version` in pkgs/wazuh-agent.nix. Wazuh supports
# an agent older than its manager. It does not support an agent newer than its
# manager, so a stale pin here fails in a way that looks like a module bug.
{
  dockerTools,
  lib,
}:
let
  version = "4.14.7";

  placeholder = "REPLACE-ME";

  # Regenerate both values together:
  #
  #   ./nixos/tests/prefetch-manager-image.sh 4.14.7
  #
  # Do not iterate on a hash mismatch that Nix reports. `imageDigest` names the
  # manifest to fetch, so a wrong digest fails during the fetch, before Nix has
  # a hash to compare. The error then names the wrong problem.
  imageDigest = placeholder;
  sha256 = placeholder;

  unpinned = imageDigest == placeholder || sha256 == placeholder;
in
lib.throwIf unpinned ''
  nixos/tests/wazuh-manager-image.nix carries no image pin.

  The enrollment check needs the wazuh/wazuh-manager:${version} image from
  Docker Hub. Nix cannot fetch it without a manifest digest and a hash, and
  neither value can be guessed.

  Run this on a host that reaches registry-1.docker.io:

    ./nixos/tests/prefetch-manager-image.sh ${version}

  Copy the imageDigest and sha256 it prints into this file.

  This affects checks.enrollment only. checks.agent needs no manager and
  still runs.
''
  {
    inherit version;

    # dockerTools.pullImage writes a tarball. virtualisation.oci-containers
    # loads it and then runs the tag, so the two must agree.
    tag = "wazuh/wazuh-manager:${version}";

    image = dockerTools.pullImage {
      imageName = "wazuh/wazuh-manager";
      finalImageTag = version;
      inherit imageDigest sha256;
    };
  }
