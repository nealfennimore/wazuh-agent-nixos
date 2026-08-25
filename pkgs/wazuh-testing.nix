# The wazuh_testing Python package, from wazuh/qa-integration-framework.
#
# The integration tests in modules/wazuh/tests/integration import this
# package. Upstream installs it with pip from GitHub. This derivation builds
# the same tag from source, so the test VM needs no network.
#
# Keep the tag in step with the modules/wazuh submodule pin. Upstream cuts a
# framework tag for every Wazuh tag, and the two move together.
{
  python3,
  fetchFromGitHub,
}:
python3.pkgs.buildPythonPackage rec {
  pname = "wazuh-testing";
  version = "4.14.7";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "wazuh";
    repo = "qa-integration-framework";
    rev = "v${version}";
    # Computed from the GitHub tarball of the tag. If the tag moves, the
    # build fails and prints the hash it saw. Paste that value here.
    hash = "sha256-RcRhRmEAlo4hNreSB14gWZXL3sD5/bBBoelQ7424/WA=";
  };

  build-system = [ python3.pkgs.setuptools ];

  # requirements.txt pins exact versions that nixpkgs no longer carries, for
  # example chardet==3.0.4 and urllib3<1.27. The framework uses none of the
  # APIs those pins protect. Strip every version bound and build against what
  # nixpkgs has.
  pythonRelaxDeps = true;

  dependencies = with python3.pkgs; [
    boto3
    chardet
    coverage
    distro
    filetype
    jsonschema
    lockfile
    psutil
    py
    pycryptodome
    pyopenssl
    pytest
    pytest-cov
    pytest-html
    pyyaml
    requests
    setuptools
    urllib3
  ];

  # The repository ships no test suite for itself.
  doCheck = false;

  pythonImportsCheck = [ "wazuh_testing" ];

  meta = {
    description = "Wazuh testing utilities for the Wazuh integration test suites";
    homepage = "https://github.com/wazuh/qa-integration-framework";
  };
}
