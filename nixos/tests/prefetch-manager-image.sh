#!/usr/bin/env bash
#
# Pin the Wazuh manager container image for checks.enrollment.
#
# The script writes wazuh-manager-image.<arch>.json next to itself. Commit that
# file. wazuh-manager-image.nix reads it and passes it to dockerTools.pullImage,
# so nothing is edited by hand.
#
# Run this on a host that reaches registry-1.docker.io.
#
# Usage:
#   ./prefetch-manager-image.sh                # 4.14.7, amd64
#   ./prefetch-manager-image.sh 4.14.7
#   ./prefetch-manager-image.sh 4.14.7 arm64
#
# The version must match `version` in pkgs/wazuh-agent.nix and `version` in
# wazuh-manager-image.nix. Wazuh supports an agent older than its manager. It
# does not support an agent newer than its manager.
#
# One run produces one architecture, so a host that runs the check on both
# must run this twice.

set -euo pipefail

VERSION="${1:-4.14.7}"
ARCH="${2:-amd64}"
IMAGE="wazuh/wazuh-manager"

# These are the two values dockerTools.pullImage accepts through go.GOARCH.
case "${ARCH}" in
	amd64 | arm64) ;;
	*)
		echo "prefetch-manager-image: unknown architecture '${ARCH}'." >&2
		echo "prefetch-manager-image: use amd64 or arm64." >&2
		exit 1
		;;
esac

if ! command -v nix >/dev/null; then
	echo "prefetch-manager-image: nix is not on the PATH." >&2
	echo "prefetch-manager-image: this script cannot run without it." >&2
	exit 1
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${here}/wazuh-manager-image.${ARCH}.json"

# Write through a temporary file in the same directory. A failed fetch must
# not replace a pin that works.
tmp="$(mktemp "${out}.XXXXXX")"
trap 'rm -f "${tmp}"' EXIT

echo "Fetching ${IMAGE}:${VERSION} for ${ARCH}." >&2
echo "The image is several gigabytes. This takes a while." >&2

nix run nixpkgs#nix-prefetch-docker -- \
	--image-name "${IMAGE}" \
	--image-tag "${VERSION}" \
	--os linux \
	--arch "${ARCH}" \
	--json >"${tmp}"

# wazuh-manager-image.nix reads these five keys by name.
for key in imageName imageDigest hash finalImageName finalImageTag; do
	if ! grep -q "\"${key}\"" "${tmp}"; then
		echo "prefetch-manager-image: the output has no ${key}." >&2
		echo "prefetch-manager-image: ${out} is unchanged." >&2
		exit 1
	fi
done

mv "${tmp}" "${out}"
trap - EXIT

echo >&2
echo "Wrote ${out}." >&2
echo >&2
echo "Commit it before you run the check. A flake copies only the files that" >&2
echo "git tracks, so an uncommitted pin is invisible to Nix and the check" >&2
echo "reports that no pin exists." >&2
