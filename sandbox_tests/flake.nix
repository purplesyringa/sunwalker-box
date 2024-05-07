{
  description = "sunwalker-box integrity testing environment";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/master";
  outputs = { self, nixpkgs }: rec {
    packages.x86_64-linux = rec {
      shell = import ./shell.nix { pkgs = nixpkgs.legacyPackages.x86_64-linux; };
      default = shell;
    };
  };
}
