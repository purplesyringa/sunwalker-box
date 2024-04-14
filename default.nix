{ pkgs ? import<nixpkgs>{},
  rust-nightly-src ? (import ./dependencies.nix { inherit pkgs; }).rust-nightly-src }:

with pkgs;

let
  src = ./.;
  cargoLockToPackageSet = lockfile: builtins.foldl' (s: q: s // { "${q.name}-${q.version}" = q; }) {} (builtins.fromTOML (builtins.readFile lockfile)).package;
  packageSetToCargoLock = packages: "version = 3\n" + (builtins.concatStringsSep "" (map (package: "\n[[package]]\n" + (builtins.concatStringsSep "\n" (map (k: "${k} = ${builtins.toJSON package."${k}"}") (builtins.attrNames package))) + "\n") (builtins.attrValues packages)));
  packageSet = (cargoLockToPackageSet "${src}/Cargo.lock") // (cargoLockToPackageSet "${rustPlatform.rustcSrc}/Cargo.lock");
in 

stdenv.mkDerivation rec {
  name = "sunwalker-box";
  inherit src;
  cargoLock = writeTextFile {
    name = "Cargo.lock";
    text = packageSetToCargoLock packageSet;
  };
  cargoDeps = rustPlatform.importCargoLock {
    lockFile = cargoLock;
    outputHashes = builtins.mapAttrs (k: v: if v.url == packageSet."${k}".source
      then v.narHash
      else throw "outdated output-hashes.json: url ${v.url}, while in Cargo.lock is ${packageSet."${k}".source}"
    ) (builtins.fromJSON (builtins.readFile ./output-hashes.json));
  };
  patchPhase = ''
    sed -i 's: +nightly: --offline:' Makefile
    sed -i 's:^    unwrap_infallible$:    unwrap_infallible,\n    file_create_new:' src/lib.rs
  '';
  nativeBuildInputs = [
    python3
    rust-nightly-src
    cargo
    rustPlatform.cargoSetupHook
    rubyPackages.seccomp-tools
  ];
  RUSTFLAGSADD = [
    "-L" "${musl}/lib"
    "-L" "${pkgsMusl.libunwind.overrideAttrs (f: { configureFlags = f.configureFlags ++ [ "--disable-shared" "--enable-static" ]; })}/lib"
    "-L" "${pkgsMusl.gcc.cc}/lib/gcc/${pkgsMusl.stdenv.targetPlatform.config}/${pkgsMusl.gcc.cc.version}"
  ];
  installPhase = ''
    mkdir -p $out/bin
    cp sunwalker_box $out/bin/
  '';
}
