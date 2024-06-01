{pkgs ? import <nixpkgs> {}}:
with pkgs; {
  libunwind = pkgsMusl.libunwind.overrideAttrs (f: {
    configureFlags =
      f.configureFlags
      ++ [
        "--disable-shared"
        "--enable-static"
      ];
  });
  rust-src = wrapRustcWith rec {
    rustc-unwrapped = rustc.unwrapped;
    sysroot = buildEnv {
      name = "rustc-sysroot";
      paths = [
        rustc-unwrapped
        (stdenv.mkDerivation {
          name = "rustc-src";
          phases = "installPhase";
          installPhase = ''
            mkdir -p $out/lib/rustlib/src
            ln -s ${rustPlatform.rustcSrc} $out/lib/rustlib/src/rust
          '';
        })
      ];
    };
  };
}
