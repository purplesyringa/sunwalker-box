{ pkgs ? import<nixpkgs>{},
  rust-nightly-src ? (import ./dependencies.nix { inherit pkgs; }).rust-nightly-src }:

with pkgs;

stdenv.mkDerivation rec {
  name = "sunwalker-box";
  src = ./.;
  cargoLock = let
    cargoLockToPackageSet = lockfile: builtins.foldl' (s: q: s // { "${builtins.toJSON [q.name q.version]}" = q; }) {} (builtins.fromTOML (builtins.readFile lockfile)).package;
    packageSetToCargoLock = packages: "version = 3\n" + (builtins.concatStringsSep "" (map (package: "\n[[package]]\n" + (builtins.concatStringsSep "\n" (map (k: "${k} = ${builtins.toJSON package."${k}"}") (builtins.attrNames package))) + "\n") (builtins.attrValues packages)));
  in writeTextFile {
    name = "Cargo.lock";
    text = packageSetToCargoLock ((cargoLockToPackageSet "${src}/Cargo.lock") // (cargoLockToPackageSet "${rustPlatform.rustcSrc}/Cargo.lock"));
  };
  cargoDeps = rustPlatform.importCargoLock {
    lockFile = cargoLock;
    # TODO: how and when to update these hashes???
    outputHashes."anyhow-1.0.79" = "1z9r9k44jr194hgmh1qxcjyw2ymx2ymrl43bikmlzm2cmib3lmgp";
    outputHashes."libc-0.2.153" = "0x9gq1q5gssgvjjzyrlzd85id2ax7hfs84d354c3mg5jcqmca2rp";
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
