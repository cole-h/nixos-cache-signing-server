{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-compat.url = "https://flakehub.com/f/edolstra/flake-compat/1.tar.gz";
  };

  outputs = { self, ... } @ inputs:
    let

      lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";

      version = "${builtins.substring 0 8 lastModifiedDate}-${self.shortRev or "dirty"}";

      forSystem = system: f: f rec {
        inherit system;
        lib = pkgs.lib;
        pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [ self.overlays.default ];
        };
      };

      forSystems = s: f: inputs.nixpkgs.lib.genAttrs s (sys: forSystem sys f);

      forAllSystems = forSystems [ "x86_64-linux" "aarch64-linux" ];

    in
    {

      overlays.default = final: prev: {
        nixos-cache-signing-server = inputs.self.packages.${final.stdenv.system}.default;
      };

      nixosModules = rec {
        default = server;
        server = import ./nixos-module.nix;
      };

      packages = forAllSystems ({ system, pkgs, ... }: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "nixos-cache-signing-server";
          version = "0.1.0-${version}";
          src = self;

          cargoLock.lockFile = ./Cargo.lock;
        };
      });

      devShells = forAllSystems ({ system, pkgs, ... }: {
        default = pkgs.mkShell {
          name = "dev";

          buildInputs = with pkgs; [
            rustc
            cargo
          ];
        };
      });

      checks = forAllSystems ({ system, pkgs, lib, ... }: {
        nixos = import ./nixos-test.nix { inherit system pkgs lib; };
      });

    };
}
