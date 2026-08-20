#!/usr/bin/env bash
#
# Print the imageDigest and sha256 for the Wazuh manager container image.
#
# Run this on a host that reaches registry-1.docker.io. Copy the two values
# into nixos/tests/wazuh-manager-image.nix. Only checks.enrollment reads them.
#
# Usage:
#   ./prefetch-manager-image.sh            # uses the version below
#   ./prefetch-manager-image.sh 4.14.7
#
# The version must match `version` in pkgs/wazuh-agent.nix. Wazuh supports an
# agent older than its manager, not an agent newer than its manager.

set -euo pipefail

VERSION="${1:-4.14.7}"
IMAGE="wazuh/wazuh-manager"

if ! command -v nix >/dev/null; then
	echo "prefetch-manager-image: nix is not on the PATH." >&2
	echo "prefetch-manager-image: this script cannot run without it." >&2
	exit 1
fi

echo "Fetching the manifest and image for ${IMAGE}:${VERSION}." >&2
echo "The image is large. This takes several minutes." >&2

nix run nixpkgs#nix-prefetch-docker -- \
	--image-name "${IMAGE}" \
	--image-tag "${VERSION}" \
	--os linux \
	--arch amd64
