{ config, lib, pkgs, ... }:
let
  cfg = config.services.cache-signing-server;

  inherit (lib)
    mkEnableOption
    mkPackageOption
    mkOption
    types
    mkIf
    ;
in
{
  options.services.cache-signing-server = {
    enable = mkEnableOption "nixos-cache-signing-server";

    package = mkPackageOption pkgs "nixos-cache-signing-server" { };

    host = mkOption {
      type = types.str;
      default = "[::]";
      description = ''
        Host to bind the server to.
      '';
    };

    port = mkOption {
      type = types.port;
      default = 8080;
      description = ''
        Port to bind the server to.
      '';
    };

    secretKeyFile = mkOption {
      type = types.str;
      description = ''
        A file holding the secret part of the cache signing key.

        A path literal or a stringly path are both acceptable and will be turned
        into strings before consumption so as not to copy the secret into the
        Nix store.
      '';
    };

    verbosity = mkOption {
      type = types.enum [ 0 1 2 ];
      default = 0;
      description = ''
        The verbosity level of logging. 0 is info, 1 is debug, 2 is trace.
      '';
    };

    logger = mkOption {
      type = types.enum [ "compact" "full" "pretty" "json" ];
      default = "compact";
      description = ''
        The logger output type to use.

        Compact:
         INFO listening on [::]:8080

        Full:
        2023-10-07T16:22:58.991894Z  INFO nixos_cache_signing_server: listening on [::]:8080

        Pretty:
          2023-10-07T16:23:32.374133Z  INFO nixos_cache_signing_server: listening on [::]:8080
            at src/main.rs:110

        Json:
        {"timestamp":"2023-10-07T16:23:50.084185Z","level":"INFO","fields":{"message":"listening on [::]:8080"},"target":"nixos_cache_signing_server"}
      '';
    };

    logDirectives = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = ''
        Tracing log directives to apply.

        See: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives
      '';
    };
  };

  config = mkIf cfg.enable {
    systemd.services.cache-signing-server = {
      description = "NixOS Cache Signing Server";
      documentation = [ "https://github.com/cole-h/nixos-cache-signing-server" ];
      wantedBy = [ "multi-user.target" ];
      wants = [ "network.target" ];
      after = [ "network-online.target" ];
      path = [ config.nix.package ];
      startLimitBurst = 5;
      startLimitIntervalSec = 10;

      serviceConfig = {
        Restart = "always";
        RestartSec = 1;
      };

      script = ''
        ${cfg.package}/bin/nixos-cache-signing-server \
          --bind ${cfg.host}:${toString cfg.port} \
          --secret-key-file ${cfg.secretKeyFile} \
          ${lib.concatStringsSep " " (lib.replicate cfg.verbosity "-v")} \
          --logger ${cfg.logger} \
          ${lib.optionalString (cfg.logDirectives != null) "--log-directives ${lib.concatStringsSep "," cfg.logDirectives}"} \
      '';
    };
  };
}

