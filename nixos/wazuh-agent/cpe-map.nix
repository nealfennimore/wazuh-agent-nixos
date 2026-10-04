# The CPE map for the Nix package inventory.
#
# The manager's vulnerability scanner looks NVD candidates up by product name
# and then rejects any candidate whose vendor the package does not carry. A
# store path carries no vendor, so without this map every NixOS package misses
# every NVD entry. This file turns nixpkgs metadata into a JSON object from
# pname to CPE vendor and product, which the wazuh-nix-inventory unit places
# beside the closure list and the collector in pkgs/patches/06 reads.
#
# The data comes from nixpkgs itself. Since February 2026 a package can set
# meta.identifiers.cpeParts, and nixpkgs derives meta.identifiers.cpe from it
# when a vendor is present. Coverage grows with every nixpkgs bump and this
# repository does not need to change for it. Three layers combine, later ones
# winning:
#
#   1. fallbacks: hand-checked CPEs for core packages nixpkgs has not
#      annotated yet. Used only where nixpkgs says nothing.
#   2. meta.identifiers of every derivation this file can see at evaluation
#      time: environment.systemPackages, the kernel, the attrNames list
#      resolved against pkgs, and any extra packages the host names.
#   3. overrides: the host's final word.
#
# The function never builds anything. It reads meta, which evaluating a
# derivation already produces.
#
# examples/show-cpe-map.sh prints the result for the flake's own nixpkgs and
# says where each entry came from.
let
  # Attribute paths in pkgs for the part of a system closure that no
  # environment.systemPackages entry names: the C library, TLS, compression,
  # the init system, shells and the usual daemons. Names this nixpkgs lacks
  # are skipped.
  defaultAttrNames = [
    "acl"
    "attr"
    "audit"
    "bash"
    "bashInteractive"
    "bind"
    "binutils"
    "bluez"
    "brotli"
    "busybox"
    "bzip2"
    "c-ares"
    "cairo"
    "chrony"
    "containerd"
    "coreutils"
    "cryptsetup"
    "cups"
    "curl"
    "cyrus_sasl"
    "dbus"
    "diffutils"
    "dnsmasq"
    "docker"
    "e2fsprogs"
    "expat"
    "ffmpeg"
    "file"
    "findutils"
    "fontconfig"
    "freetype"
    "gawk"
    "gcc"
    "gdb"
    "gdk-pixbuf"
    "gettext"
    "git"
    "glib"
    "glibc"
    "gmp"
    "gnugrep"
    "gnumake"
    "gnupg"
    "gnused"
    "gnutar"
    "gnutls"
    "go"
    "gzip"
    "haproxy"
    "harfbuzz"
    "icu"
    "imagemagick"
    "iproute2"
    "iptables"
    "jq"
    "kmod"
    "krb5"
    "less"
    "libarchive"
    "libassuan"
    "libcap"
    "libevent"
    "libffi"
    "libgcrypt"
    "libgit2"
    "libgpg-error"
    "libidn2"
    "libjpeg_turbo"
    "libksba"
    "libpcap"
    "libpng"
    "libpsl"
    "libseccomp"
    "libsodium"
    "libssh2"
    "libtasn1"
    "libtiff"
    "libunistring"
    "libuv"
    "libwebp"
    "libxml2"
    "libxslt"
    "libyaml"
    "linux-pam"
    "lvm2"
    "lz4"
    "mariadb"
    "mesa"
    "ncurses"
    "nettle"
    "networkmanager"
    "nftables"
    "nghttp2"
    "nginx"
    "nix"
    "nodejs"
    "nspr"
    "nss"
    "openldap"
    "openssh"
    "openssl"
    "openvpn"
    "p11-kit"
    "pango"
    "patch"
    "pcre2"
    "perl"
    "pipewire"
    "polkit"
    "postgresql"
    "python3"
    "qemu"
    "readline"
    "redis"
    "runc"
    "rustc"
    "samba"
    "shadow"
    "sqlite"
    "sudo"
    "systemd"
    "tcpdump"
    "unbound"
    "util-linux"
    "vim"
    "wget"
    "which"
    "wpa_supplicant"
    "xorg.libX11"
    "xorg.xorgserver"
    "xz"
    "zlib"
    "zstd"
  ];

  # CPE vendors and products for pnames that nixpkgs has not annotated. Each
  # entry was checked against the NVD CPE dictionary by hand. Keys are
  # lower-case pnames as they appear in store paths, so "gnutar" and not
  # "tar". nixpkgs metadata overrides these as it arrives.
  defaultFallbacks = {
    "bash" = { vendor = "gnu"; product = "bash"; };
    "bash-interactive" = { vendor = "gnu"; product = "bash"; };
    "binutils" = { vendor = "gnu"; product = "binutils"; };
    "bind" = { vendor = "isc"; product = "bind"; };
    "brotli" = { vendor = "google"; product = "brotli"; };
    "busybox" = { vendor = "busybox"; product = "busybox"; };
    "bzip2" = { vendor = "bzip"; product = "bzip2"; };
    "c-ares" = { vendor = "c-ares_project"; product = "c-ares"; };
    "cairo" = { vendor = "cairographics"; product = "cairo"; };
    "containerd" = { vendor = "linuxfoundation"; product = "containerd"; };
    "coreutils" = { vendor = "gnu"; product = "coreutils"; };
    "dbus" = { vendor = "freedesktop"; product = "dbus"; };
    "diffutils" = { vendor = "gnu"; product = "diffutils"; };
    "dnsmasq" = { vendor = "thekelleys"; product = "dnsmasq"; };
    "e2fsprogs" = { vendor = "e2fsprogs_project"; product = "e2fsprogs"; };
    "expat" = { vendor = "libexpat_project"; product = "libexpat"; };
    "ffmpeg" = { vendor = "ffmpeg"; product = "ffmpeg"; };
    "findutils" = { vendor = "gnu"; product = "findutils"; };
    "fontconfig" = { vendor = "fontconfig_project"; product = "fontconfig"; };
    "freetype" = { vendor = "freetype"; product = "freetype"; };
    "gawk" = { vendor = "gnu"; product = "gawk"; };
    "gcc" = { vendor = "gnu"; product = "gcc"; };
    "gdb" = { vendor = "gnu"; product = "gdb"; };
    "gettext" = { vendor = "gnu"; product = "gettext"; };
    "git" = { vendor = "git-scm"; product = "git"; };
    "glib" = { vendor = "gnome"; product = "glib"; };
    "glibc" = { vendor = "gnu"; product = "glibc"; };
    "gmp" = { vendor = "gmplib"; product = "gmp"; };
    "gnugrep" = { vendor = "gnu"; product = "grep"; };
    "gnumake" = { vendor = "gnu"; product = "make"; };
    "gnupg" = { vendor = "gnupg"; product = "gnupg"; };
    "gnused" = { vendor = "gnu"; product = "sed"; };
    "gnutar" = { vendor = "gnu"; product = "tar"; };
    "gnutls" = { vendor = "gnu"; product = "gnutls"; };
    "go" = { vendor = "golang"; product = "go"; };
    "gzip" = { vendor = "gnu"; product = "gzip"; };
    "haproxy" = { vendor = "haproxy"; product = "haproxy"; };
    "harfbuzz" = { vendor = "harfbuzz_project"; product = "harfbuzz"; };
    "icu4c" = { vendor = "icu-project"; product = "international_components_for_unicode"; };
    "imagemagick" = { vendor = "imagemagick"; product = "imagemagick"; };
    "iptables" = { vendor = "netfilter"; product = "iptables"; };
    "jq" = { vendor = "jq_project"; product = "jq"; };
    "kmod" = { vendor = "kernel"; product = "kmod"; };
    "krb5" = { vendor = "mit"; product = "kerberos_5"; };
    "less" = { vendor = "gnu"; product = "less"; };
    "libarchive" = { vendor = "libarchive"; product = "libarchive"; };
    "libassuan" = { vendor = "gnupg"; product = "libassuan"; };
    "libffi" = { vendor = "libffi_project"; product = "libffi"; };
    "libgcrypt" = { vendor = "gnupg"; product = "libgcrypt"; };
    "libgit2" = { vendor = "libgit2"; product = "libgit2"; };
    "libgpg-error" = { vendor = "gnupg"; product = "libgpg-error"; };
    "libidn2" = { vendor = "gnu"; product = "libidn2"; };
    "libjpeg-turbo" = { vendor = "libjpeg-turbo"; product = "libjpeg-turbo"; };
    "libksba" = { vendor = "gnupg"; product = "libksba"; };
    "libpcap" = { vendor = "tcpdump"; product = "libpcap"; };
    "libpng" = { vendor = "libpng"; product = "libpng"; };
    "libseccomp" = { vendor = "libseccomp_project"; product = "libseccomp"; };
    "libssh2" = { vendor = "libssh2"; product = "libssh2"; };
    "libtasn1" = { vendor = "gnu"; product = "libtasn1"; };
    "libtiff" = { vendor = "libtiff"; product = "libtiff"; };
    "libunistring" = { vendor = "gnu"; product = "libunistring"; };
    "libuv" = { vendor = "libuv"; product = "libuv"; };
    "libwebp" = { vendor = "webmproject"; product = "libwebp"; };
    "libxml2" = { vendor = "xmlsoft"; product = "libxml2"; };
    "libxslt" = { vendor = "xmlsoft"; product = "libxslt"; };
    "libyaml" = { vendor = "pyyaml"; product = "libyaml"; };
    "linux" = { vendor = "linux"; product = "linux_kernel"; };
    "linux-pam" = { vendor = "linux-pam"; product = "linux-pam"; };
    "lz4" = { vendor = "lz4_project"; product = "lz4"; };
    "mariadb" = { vendor = "mariadb"; product = "mariadb"; };
    "mesa" = { vendor = "mesa3d"; product = "mesa"; };
    "ncurses" = { vendor = "gnu"; product = "ncurses"; };
    "nghttp2" = { vendor = "nghttp2"; product = "nghttp2"; };
    "nginx" = { vendor = "f5"; product = "nginx"; };
    "nix" = { vendor = "nixos"; product = "nix"; };
    "nodejs" = { vendor = "nodejs"; product = "node.js"; };
    "nspr" = { vendor = "mozilla"; product = "nspr"; };
    "nss" = { vendor = "mozilla"; product = "nss"; };
    "openldap" = { vendor = "openldap"; product = "openldap"; };
    "openssh" = { vendor = "openbsd"; product = "openssh"; };
    "openssl" = { vendor = "openssl"; product = "openssl"; };
    "openvpn" = { vendor = "openvpn"; product = "openvpn"; };
    "p11-kit" = { vendor = "p11-kit_project"; product = "p11-kit"; };
    "pango" = { vendor = "gnome"; product = "pango"; };
    "patch" = { vendor = "gnu"; product = "patch"; };
    "pcre2" = { vendor = "pcre"; product = "pcre2"; };
    "perl" = { vendor = "perl"; product = "perl"; };
    "polkit" = { vendor = "polkit_project"; product = "polkit"; };
    "postgresql" = { vendor = "postgresql"; product = "postgresql"; };
    "python3" = { vendor = "python"; product = "python"; };
    "qemu" = { vendor = "qemu"; product = "qemu"; };
    "readline" = { vendor = "gnu"; product = "readline"; };
    "redis" = { vendor = "redis"; product = "redis"; };
    "runc" = { vendor = "linuxfoundation"; product = "runc"; };
    "rustc" = { vendor = "rust-lang"; product = "rust"; };
    "samba" = { vendor = "samba"; product = "samba"; };
    "sqlite" = { vendor = "sqlite"; product = "sqlite"; };
    "sudo" = { vendor = "sudo_project"; product = "sudo"; };
    "systemd" = { vendor = "systemd_project"; product = "systemd"; };
    "tcpdump" = { vendor = "tcpdump"; product = "tcpdump"; };
    "unbound" = { vendor = "nlnetlabs"; product = "unbound"; };
    "util-linux" = { vendor = "kernel"; product = "util-linux"; };
    "vim" = { vendor = "vim"; product = "vim"; };
    "wget" = { vendor = "gnu"; product = "wget"; };
    "xz" = { vendor = "tukaani"; product = "xz"; };
    "zlib" = { vendor = "zlib"; product = "zlib"; };
    "zstd" = { vendor = "facebook"; product = "zstandard"; };
  };

  # One package's entry from its nixpkgs metadata, or null. nixpkgs sets
  # meta.identifiers.cpe only once the package declares a vendor, so that
  # attribute is the test for "annotated". The product defaults to the pname
  # in nixpkgs too, so reading it back is safe.
  #
  # tryEval catches a throw inside meta, such as an alias for a removed
  # package. It does not catch a missing attribute, so every access below
  # tests presence first.
  entryFromMeta =
    lib: drv:
    let
      result = builtins.tryEval (
        let
          identifiers = drv.meta.identifiers or { };
          parts = identifiers.cpeParts or { };
        in
        if drv ? pname && identifiers ? cpe && parts ? vendor then
          {
            name = lib.toLower drv.pname;
            value = {
              vendor = lib.toLower parts.vendor;
              product = lib.toLower (parts.product or drv.pname);
            };
          }
        else
          null
      );
    in
    if result.success then result.value else null;

  # pkgs.<path>, or null when the attribute is absent or throws.
  resolve =
    lib: pkgs: attrPath:
    let
      result = builtins.tryEval (
        let
          value = lib.attrByPath (lib.splitString "." attrPath) null pkgs;
        in
        if lib.isDerivation value then value else null
      );
    in
    if result.success then result.value else null;

  # The derivations to read: the named attributes plus the given list.
  candidates =
    {
      lib,
      pkgs,
      packages ? [ ],
      attrNames ? defaultAttrNames,
      ...
    }:
    lib.filter (drv: drv != null) (map (resolve lib pkgs) attrNames) ++ packages;

  fromMeta =
    args@{ lib, ... }:
    lib.listToAttrs (lib.filter (entry: entry != null) (map (entryFromMeta lib) (candidates args)));

  # The map: pname -> { vendor, product }.
  build =
    args@{
      lib,
      pkgs,
      packages ? [ ],
      attrNames ? defaultAttrNames,
      fallbacks ? defaultFallbacks,
      overrides ? { },
    }:
    fallbacks // fromMeta args // overrides;

  # The same, with provenance. For examples/show-cpe-map.sh.
  report =
    args@{
      lib,
      pkgs,
      packages ? [ ],
      attrNames ? defaultAttrNames,
      fallbacks ? defaultFallbacks,
      overrides ? { },
    }:
    let
      meta = fromMeta args;
      map' = build args;
      drvs = candidates args;
      pnames = lib.unique (map (drv: lib.toLower drv.pname) (lib.filter (drv: drv ? pname) drvs));
      source =
        pname:
        if overrides ? ${pname} then
          "override"
        else if meta ? ${pname} then
          "nixpkgs meta.identifiers"
        else if fallbacks ? ${pname} then
          "fallback"
        else
          null;
    in
    {
      map = map';
      source = lib.mapAttrs (pname: _: source pname) map';
      # Packages this file looked at that neither nixpkgs nor the fallbacks
      # know a vendor for. Candidates for a fallback entry, or for an
      # upstream nixpkgs PR.
      unresolved = lib.filter (pname: source pname == null) pnames;
      counts = {
        evaluated = lib.length pnames;
        fromMeta = lib.length (lib.attrNames meta);
        fromFallbacks = lib.length (lib.filter (pname: source pname == "fallback") (lib.attrNames map'));
        fromOverrides = lib.length (lib.attrNames overrides);
        total = lib.length (lib.attrNames map');
      };
    };
in
{
  inherit
    defaultAttrNames
    defaultFallbacks
    build
    report
    ;
}
