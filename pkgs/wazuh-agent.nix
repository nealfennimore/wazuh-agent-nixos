{
  autoconf,
  automake,
  clang,
  cmake,
  curl,
  elfutils,
  fetchFromGitHub,
  fetchurl,
  lib,
  libbfd,
  libbpf,
  libcap,
  libelf,
  libgcc,
  libtool,
  llvm,
  openssl,
  patchelf,
  perl,
  pkg-config,
  policycoreutils,
  python312,
  removeReferencesTo,
  stdenv,
  systemd,
  zlib,
  ...
}: let
  # Keep these three in step with the modules/wazuh submodule pin.
  # dependencyVersion mirrors DEPS_VERSION in src/Makefile at the same tag.
  version = "4.14.7";
  dependencyVersion = "54";
  wazuhRev = "a42268a27c555d9348d5598fb8751eaf4c8e9024";

  external_dependencies = import ./dependencies {
    inherit fetchurl lib dependencyVersion;
  };

  # modules/wazuh is a git submodule. Nix only sees its contents when the flake
  # is evaluated with submodules enabled, for example:
  #   nix build 'git+file:///path/to/repo?submodules=1#wazuh-agent'
  # When it is empty, fall back to fetching the same commit, so a plain
  # `nix build .#wazuh-agent` still works.
  submodule = ../modules/wazuh;
  haveSubmodule = builtins.pathExists (submodule + "/src/Makefile");
  wazuhSrc =
    if haveSubmodule
    then submodule
    else
      fetchFromGitHub {
        owner = "wazuh";
        repo = "wazuh";
        rev = wazuhRev;
        sha256 = "sha256-GILu5/EvaN4XeeUqiz6cAFNiZHw0yAGbLuyUBxPrLj0=";
      };

  # rev mirrors HTTP_REQUEST_BRANCH in src/Makefile at the same tag.
  wazuh-http-request = fetchFromGitHub {
    owner = "wazuh";
    repo = "wazuh-http-request";
    rev = "cd50797cfe03c27f3759bdc243fecca6f7535d35";
    sha256 = "sha256-K8wgvsoOeCJyn1z9P7E/g2w7x0Jt5BjUhakK1eyUYeA=";
  };

  libbpf_bootstrap_deps = {
    bootstrap = fetchFromGitHub {
      owner = "libbpf";
      repo = "libbpf-bootstrap";
      rev = "aa18cc0d8fc8ef4104fb74d218ae6a20cf6eb176";
      sha256 = "sha256-ggIDf/I4QlSypFpsRibsdWd9bSevC2mfyEenlYZQdqI=";
      fetchSubmodules = true;
    };
    # 02-libbpf-bootstrap.patch disables the CMake download of this file, so the
    # derivation supplies it instead.
    modern_bpf_c = fetchurl {
      url = "https://raw.githubusercontent.com/wazuh/wazuh/v${version}/src/syscheckd/src/ebpf/src/modern.bpf.c";
      hash = "sha256-zVqJXLW9tTxX0ncJAHVE2JIJDrRTAd2x7TA+DZ4hrWk=";
    };
  };
in
  stdenv.mkDerivation {
    pname = "wazuh-agent";
    inherit version;
    src = wazuhSrc;

    dontConfigure = true;

    # install.sh writes the output tree itself, with modes that fixupPhase
    # rewrites. Revisit this once a build passes end to end.
    dontFixup = true;

    hardeningDisable = [
      "zerocallusedregs"
    ];

    nativeBuildInputs = [
      autoconf
      automake
      clang
      cmake
      curl
      perl
      pkg-config
      policycoreutils
      python312
      zlib
    ];

    buildInputs = [
      elfutils
      libbfd
      libbpf
      libcap
      libelf
      libtool
      llvm
      openssl
    ];

    makeFlags = [
      "-C src"
      "TARGET=agent"
      "INSTALLDIR=$out"
    ];

    patches = [
      ./patches/01-nixos-build-and-homedir.patch
    ];

    # GCC 13 and later reject the incompatible pointer types in the vendored
    # libdb sources, which upstream still builds as warnings.
    env.NIX_CFLAGS_COMPILE = toString [
      "-Wno-error=incompatible-pointer-types"
      "-Wno-error=implicit-function-declaration"
      "-Wno-error=int-conversion"
    ];

    unpackPhase = ''
      runHook preUnpack

      cp -rf --no-preserve=all "$src"/* .

      mkdir -p src/external
      ${lib.concatMapStringsSep "\n" (
          dep: "tar -xzf ${dep} -C src/external"
        )
        external_dependencies}

      mkdir -p src/external/libbpf-bootstrap/src
      cp --no-preserve=all -rf ${libbpf_bootstrap_deps.bootstrap}/* src/external/libbpf-bootstrap
      cp ${libbpf_bootstrap_deps.modern_bpf_c} src/external/libbpf-bootstrap/src/modern.bpf.c

      cp --no-preserve=all -rf ${wazuh-http-request}/* src/shared_modules/http-request/

      runHook postUnpack
    '';

    prePatch = ''
      substituteInPlace src/init/wazuh-server.sh \
        --replace-fail "cd ''${LOCAL}" ""

      substituteInPlace src/external/audit-userspace/autogen.sh \
        --replace-warn "cp INSTALL.tmp INSTALL" ""

      substituteInPlace src/external/openssl/config \
        --replace-warn "/usr/bin/env" "env"

      substituteInPlace src/init/inst-functions.sh \
        --replace-warn "WAZUH_GROUP='wazuh'" "WAZUH_GROUP='nixbld'" \
        --replace-warn "WAZUH_USER='wazuh'" "WAZUH_USER='nixbld'"

      substituteInPlace src/external/libbpf-bootstrap/CMakeLists.txt \
        --replace-fail "/usr/bin/clang" "${clang}/bin/clang"

      # This CMakeLists.txt ships in the DEPS_VERSION ${dependencyVersion}
      # libbpf-bootstrap tarball, not in wazuh/wazuh, so it changes without
      # showing up in any Wazuh tag. A context patch against it broke on the
      # 40 to 54 move. These edits key off structure instead of line context.
      #
      # They do three things:
      #   - stop ExternalProject_Add from cloning libbpf, bpftool, and
      #     vmlinux.h. The derivation supplies all three.
      #   - stop the CMake download of modern.bpf.c. The derivation supplies it.
      #   - relax two errors that current clang raises and upstream does not.
      cmake_lists=src/external/libbpf-bootstrap/CMakeLists.txt

      for anchor in 'GIT_REPOSITORY' 'PREFIX ' 'bpf_object(modern'; do
        grep -q "$anchor" "$cmake_lists" || {
          echo "prePatch: anchor '$anchor' is gone from $cmake_lists." >&2
          echo "prePatch: libbpf-bootstrap changed shape. Rework these edits." >&2
          exit 1
        }
      done

      sed -i \
        -e '/GIT_REPOSITORY/d' \
        -e '/GIT_TAG/d' \
        -e '/DOWNLOAD_COMMAND/d' \
        -e '/file(DOWNLOAD/d' \
        -e '/file(SIZE/d' \
        -e 's|^\([[:space:]]*\)PREFIX \(.*\)$|\1PREFIX \2\n\1DOWNLOAD_COMMAND ""|' \
        -e 's|^\([[:space:]]*\)bpf_object(modern|\1set(CMAKE_C_FLAGS "''${CMAKE_C_FLAGS} -Wno-error=implicit-function-declaration -Wno-error=int-conversion")\n\1bpf_object(modern|' \
        "$cmake_lists"

      # The download is gone, so FILE_SIZE is never set and this guard would
      # fire on an empty variable.
      substituteInPlace "$cmake_lists" \
        --replace-warn 'if(NOT EXISTS ''${DEST_PATH} OR FILE_SIZE EQUAL 0)' \
                       'if(NOT EXISTS ''${DEST_PATH})'

      if grep -q 'GIT_REPOSITORY\|file(DOWNLOAD' "$cmake_lists"; then
        echo "prePatch: $cmake_lists still fetches from the network." >&2
        exit 1
      fi

      cat << EOF > "etc/preloaded-vars.conf"
      USER_LANGUAGE="en"
      USER_NO_STOP="y"
      USER_INSTALL_TYPE="agent"
      USER_DIR="$out"
      USER_DELETE_DIR="n"
      USER_ENABLE_ACTIVE_RESPONSE="y"
      USER_ENABLE_SYSCHECK="n"
      USER_ENABLE_ROOTCHECK="y"
      USER_AGENT_SERVER_IP=127.0.0.1
      USER_CA_STORE="n"
      EOF
    '';

    preBuild = ''
      make -C src TARGET=agent settings
      make -C src TARGET=agent INSTALLDIR=$out deps
    '';

    installPhase = ''
      runHook preInstall

      mkdir -p $out/{bin,etc/shared,queue,var,wodles,logs,lib,tmp,agentless,active-response}

      substituteInPlace install.sh \
        --replace-warn "Xroot" "Xnixbld"
      chmod u+x install.sh

      INSTALLDIR=$out USER_DIR=$out ./install.sh binary-install

      substituteInPlace $out/bin/wazuh-control \
        --replace-fail "cd ''${LOCAL}" "#"

      chmod u+x $out/bin/* $out/active-response/bin/*

      # The NixOS module reads this to build ossec.conf. Keeping a copy in the
      # output removes the evaluation-time fetch the module used to do.
      install -Dm444 etc/ossec-agent.conf $out/share/wazuh-agent/ossec-agent.conf

      ${removeReferencesTo}/bin/remove-references-to \
        -t ${libgcc.out} \
        $out/lib/*

      ${patchelf}/bin/patchelf --add-rpath ${systemd}/lib $out/bin/wazuh-logcollector

      rm -rf $out/src

      runHook postInstall
    '';

    meta = {
      description = "Wazuh agent";
      homepage = "https://wazuh.com";
      license = lib.licenses.gpl2Only;
      platforms = lib.platforms.linux;
      mainProgram = "wazuh-control";
    };
  }
