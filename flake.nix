{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.poetry2nix.url = "github:nix-community/poetry2nix";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = {
    self,
    nixpkgs,
    poetry2nix,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [
          #      (import rust-overlay)
          poetry2nix.overlays.default
        ];
      };
    in {
      packages = let
        inherit (poetry2nix.lib.mkPoetry2Nix {pkgs = pkgs.${system};}) mkPoetryApplication;
      in {
        #  default = mkPoetryApplication {projectDir = self;};
      };

      formatter = pkgs.alejandra;

      devShells = let
        inherit (poetry2nix.lib.mkPoetry2Nix {inherit pkgs;}) mkPoetryEnv;
      in {
        default = pkgs.mkShellNoCC {
          packages = with pkgs; [
            #(mkPoetryEnv {projectDir = self;})
            python312Full
            black
            poetry
          ];
          shellHook = ''
            poetry add $(cat app/requirements.txt)
            poetry install
          '';
        };
      };
    });
}
