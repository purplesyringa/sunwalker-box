{pkgs ? import <nixpkgs> {}}:
with pkgs; {
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
  rubyPackages = rec {
    os = buildRubyGem {
      name = "os";
      gemName = "os";
      source.sha256 = "0gwd20smyhxbm687vdikfh1gpi96h8qb1x28s2pdcysf6dm6v0ap";
      version = "1.1.4";
    };
    seccomp-tools = buildRubyGem {
      name = "seccomp-tools";
      gemName = "seccomp-tools";
      src = fetchFromGitHub {
        owner = "david942j";
        repo = "seccomp-tools";
        rev = "cefb30662f52dfdec2505e5b4e1e6ea014c142bb";
        sha256 = "0pq2k6z8y7zzfgp8b02a5qxriln3l97vy9pkys8kia1iilijfl3g";
      };
      propagatedBuildInputs = [os];
    };
  };
}
