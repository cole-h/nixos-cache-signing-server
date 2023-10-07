{ system, pkgs, lib, ... }:
let
  testTools = import (pkgs.path + "/nixos/lib/testing-python.nix") { inherit system pkgs; };
in
testTools.runTest {
  name = "nixos-cache-signing-server";
  meta.maintainers = with lib.maintainers; [ cole-h ];
  node.pkgs = pkgs;

  nodes.machine =
    { pkgs, config, ... }:
    {
      imports = [ ./nixos-module.nix ];
      nix.settings.extra-experimental-features = [ "nix-command" "flakes" ];
      environment.systemPackages = [ pkgs.jq ];
      environment.etc."secret-key".text = builtins.readFile ./secret-key;

      environment.etc."unsigned-path1".source = pkgs.runCommand "unsigned-path1" { } ''
        echo $out > $out
      '';

      environment.etc."unsigned-path2".source = pkgs.runCommand "unsigned-path2" { } ''
        echo $out > $out
      '';

      services.cache-signing-server = {
        enable = true;
        verbosity = 2;
        secretKeyFile = "/etc/secret-key";
      };
    };

  testScript =
    ''
      import json

      start_all()
      machine.wait_for_unit("network-online.target")
      machine.wait_for_unit("cache-signing-server.service")
      machine.wait_until_succeeds("nc -z localhost 8080")

      with subtest("pubkey should match"):
        pubkey = machine.succeed("curl -ss http://localhost:8080/publickey")

        if "${builtins.readFile ./public-key}" != pubkey:
          raise Exception("pubkey didn't match")

      with subtest("server should produce same signature as nix"):
        with subtest("using the store path"):
          signature = machine.succeed("curl -ss http://localhost:8080/sign-store-path --data-raw $(cat /etc/unsigned-path1)")
          machine.succeed("nix store sign -k /etc/secret-key $(cat /etc/unsigned-path1)")
          nix_signatures = machine.succeed("nix path-info --json $(cat /etc/unsigned-path1) | jq .[].signatures")
          nix_signatures_json = json.loads(nix_signatures)

          if signature not in nix_signatures_json:
            raise Exception("signatures didn't match")

        with subtest("using the fingerprint"):
          base32_nar_hash = machine.succeed("""
            echo -n sha256:"$(nix hash to-base32 --type sha256 "$(nix path-info --json $(cat /etc/unsigned-path2) | jq -r '.[].narHash')")"
          """)
          fingerprint = machine.succeed(f"""
            echo -n "$(nix path-info --json $(cat /etc/unsigned-path2) | jq -r '.[] | "1;\(.path);{base32_nar_hash};\(.narSize);\(.references | join(","))"')"
          """)
          signature = machine.succeed(f"curl -ss http://localhost:8080/sign --data-raw '{fingerprint}'")
          machine.succeed("nix store sign -k /etc/secret-key $(cat /etc/unsigned-path2)")
          nix_signatures = machine.succeed("nix path-info --json $(cat /etc/unsigned-path2) | jq .[].signatures")
          nix_signatures_json = json.loads(nix_signatures)

          if signature not in nix_signatures_json:
            raise Exception("signatures didn't match")
    '';
}

