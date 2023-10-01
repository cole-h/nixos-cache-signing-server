{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, ... } @ inputs:
    let

      lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";

      version = "${builtins.substring 0 8 lastModifiedDate}-${self.shortRev or "dirty"}";

      forSystems = s: f: inputs.nixpkgs.lib.genAttrs s (system: f rec {
        inherit system;
        pkgs = import inputs.nixpkgs { inherit system; };
        lib = pkgs.lib;
      });

      forAllSystems = forSystems [ "x86_64-linux" "aarch64-linux" ];

    in
    {

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

    };
}
