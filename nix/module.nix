self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  hostProxyConfiguration = config.services.hostProxy;
  package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
  routesSpecification = lib.concatStringsSep "," (
    lib.mapAttrsToList (
      hostname: upstreamAddress: "${hostname}=${upstreamAddress}"
    ) hostProxyConfiguration.routes
  );
in
{
  options.services.hostProxy = {
    enable = lib.mkEnableOption "the host reverse proxy on ports 80 and 443";

    routes = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      description = ''
        Map from public hostname to local upstream address. Matching is
        exact, so subdomains need their own entries. Requests for hosts
        not listed here receive a 404.
      '';
      example = {
        "example.org" = "127.0.0.1:3000";
        "www.example.org" = "127.0.0.1:3000";
      };
    };

    certificateFile = lib.mkOption {
      type = lib.types.str;
      description = ''
        Path to the PEM certificate presented on port 443. Must be
        readable by the host-proxy user and cover every hostname in
        routes.
      '';
    };

    privateKeyFile = lib.mkOption {
      type = lib.types.str;
      description = "Path to the PEM private key for certificateFile.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Open TCP ports 80 and 443 in the firewall.";
    };
  };

  config = lib.mkIf hostProxyConfiguration.enable {
    users.users.host-proxy = {
      isSystemUser = true;
      group = "host-proxy";
    };
    users.groups.host-proxy = { };

    networking.firewall.allowedTCPPorts = lib.mkIf hostProxyConfiguration.openFirewall [
      80
      443
    ];

    systemd.services.hostProxy = {
      description = "Host reverse proxy";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        HOST_PROXY_ROUTES = routesSpecification;
        HOST_PROXY_CERTIFICATE_FILE = hostProxyConfiguration.certificateFile;
        HOST_PROXY_PRIVATE_KEY_FILE = hostProxyConfiguration.privateKeyFile;
        RUST_LOG = "info";
      };

      serviceConfig = {
        ExecStart = "${package}/bin/host-proxy";
        User = "host-proxy";
        Group = "host-proxy";
        Restart = "on-failure";
        RestartSec = 5;

        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];

        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        RestrictSUIDSGID = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        ProtectControlGroups = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
      };
    };
  };
}
