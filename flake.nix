{
  description = "Secure sandbox for competitive programming competitions";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/master";
  outputs = {
    self,
    nixpkgs,
  }: rec {
    formatter.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.alejandra;
    packages.x86_64-linux = let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in rec {
      sunwalker-box = import ./default.nix {inherit pkgs;};
      testenv = import ./sandbox_tests/shell.nix {
        inherit pkgs;
        inherit sunwalker-box;
      };
      default = sunwalker-box;
    };
  };
}
