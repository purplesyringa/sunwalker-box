{
  pkgs ? import <nixpkgs> {},
  deps ? import ./dependencies.nix {inherit pkgs;},
}:
with pkgs; let
  fs = lib.fileset;
  src = ./.;
  drvSrc = fs.toSource {
    root = src;
    fileset = fs.difference src (
      fs.unions [
        (fs.maybeMissing ./result)
        ./sandbox_tests
      ]
    );
  };
  cargoLockToPackageSet = lockfile:
    builtins.foldl' (s: q: s // {"${q.name}-${q.version}" = q;}) {}
    (builtins.fromTOML (builtins.readFile lockfile)).package;
  packageSetToCargoLock = packages:
    ''
      version = 3
    ''
    + (builtins.concatStringsSep "" (
      map (
        package:
          ''

            [[package]]
          ''
          + (builtins.concatStringsSep "\n" (
            map (k: "${k} = ${builtins.toJSON package."${k}"}") (builtins.attrNames package)
          ))
          + "\n"
      ) (builtins.attrValues packages)
    ));
  packageSet =
    (cargoLockToPackageSet "${src}/Cargo.lock")
    // (cargoLockToPackageSet "${rustPlatform.rustcSrc}/Cargo.lock");
in
  stdenv.mkDerivation rec {
    name = "sunwalker-box";
    src = drvSrc;
    cargoDeps = rustPlatform.importCargoLock {
      lockFileContents = packageSetToCargoLock packageSet;
      allowBuiltinFetchGit = true;
    };
    patchPhase = ''
      sed -i 's: +nightly: --offline:' Makefile
    '';
    nativeBuildInputs = [
      python3
      deps.rust-src
      cargo
      rustPlatform.cargoSetupHook
      rubyPackages.seccomp-tools
    ];
    RUSTC_BOOTSTRAP = 1;
    RUSTFLAGSADD = [
      "-L"
      "${musl}/lib"
      "-L"
      "${deps.libunwind}/lib"
      "-L"
      "${pkgsMusl.gcc.cc}/lib/gcc/${pkgsMusl.stdenv.targetPlatform.config}/${pkgsMusl.gcc.cc.version}"
    ];
    installPhase = ''
      mkdir -p $out/bin
      cp sunwalker_box $out/bin/
    '';
  }
