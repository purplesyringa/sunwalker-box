{
  pkgs ? import <nixpkgs> {},
  sunwalker-box,
}:
with pkgs;
  pkgs.mkShellNoCC {
    src = ./.;
    nativeBuildInputs = [
      pkgsMusl.gcc
      sunwalker-box
      python3
      python3Packages.pyyaml
    ];
  }
