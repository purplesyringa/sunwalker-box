{pkgs ? import <nixpkgs> {}}:
with pkgs;
  pkgs.mkShellNoCC {
    src = ./.;
    nativeBuildInputs = [
      pkgsMusl.gcc
      python3
      python3Packages.pyyaml

      # Do not provide `sunwalker-box` on purpose. This is an *environment* for running sandbox
      # tests, but not the environment for testing *current* box. This allows building the box
      # without nix.
    ];
  }
