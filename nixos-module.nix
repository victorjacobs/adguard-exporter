{ self }:
{
  config,
  lib,
  pkgs,
  utils,
  ...
}:

let
  cfg = config.services.adguard-exporter;
in
{
  options.services.adguard-exporter = {
    enable = lib.mkEnableOption "the AdGuard Home Prometheus exporter";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "adguard-exporter.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = "The adguard-exporter package to use.";
    };

    adguardUrl = lib.mkOption {
      type = lib.types.str;
      default = "http://localhost:3000";
      description = "AdGuard Home base URL.";
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/run/secrets/adguard-exporter";
      description = ''
        Environment file containing ADGUARD_USERNAME and ADGUARD_PASSWORD.
        Keep this file outside the Nix store because it contains credentials.
      '';
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Address on which to expose metrics.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 9617;
      description = "Port on which to expose metrics.";
    };

    telemetryPath = lib.mkOption {
      type = lib.types.str;
      default = "/metrics";
      description = "HTTP path on which to expose metrics.";
    };

    logLevel = lib.mkOption {
      type = lib.types.enum [
        "debug"
        "info"
        "warn"
        "error"
      ];
      default = "info";
      description = "Exporter log level.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to open the exporter port in the firewall.";
    };
  };

  config = lib.mkIf cfg.enable {
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    systemd.services.adguard-exporter = {
      description = "AdGuard Home Prometheus exporter";
      documentation = [ "https://github.com/victorjacobs/adguard-exporter" ];
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      serviceConfig = {
        DynamicUser = true;
        ExecStart = utils.escapeSystemdExecArgs [
          (lib.getExe cfg.package)
          "--adguard.url"
          cfg.adguardUrl
          "--web.listen-address"
          "${cfg.listenAddress}:${toString cfg.port}"
          "--web.telemetry-path"
          cfg.telemetryPath
          "--log.level"
          cfg.logLevel
        ];
        Restart = "on-failure";

        CapabilityBoundingSet = "";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        UMask = "0077";
      }
      // lib.optionalAttrs (cfg.environmentFile != null) {
        EnvironmentFile = cfg.environmentFile;
      };
    };
  };
}
