{ pkgs ? import <nixpkgs> {} }:

with pkgs;

pkgs.mkShellNoCC {
    src = ./.;
    nativeBuildInputs = [
        pkgsMusl.gcc
        (callPackage ../default.nix {})
        python3
        python3Packages.pyyaml
    ];
}
