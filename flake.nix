{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.callPackage ./package.nix { };

        formatter = pkgs.nixfmt-tree;

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go_1_26
            gopls
            gotools
          ];
        };
      }
    )
    // {
      nixosModules.default = import ./nixos-module.nix { inherit self; };
    };
}
