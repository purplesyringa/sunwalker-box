{
  description = "Secure sandbox for competitive programming competitions";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/master";
  outputs = { self, nixpkgs }: rec {
    packages.x86_64-linux = rec {
      sunwalker-box = import ./default.nix { pkgs = nixpkgs.legacyPackages.x86_64-linux; };
      default = sunwalker-box;
    };
  };
}
