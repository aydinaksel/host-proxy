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
      hostname: route:
      if route.redirectTo != null then
        "${hostname}=>${route.redirectTo}"
      else
        let
          accessTag = if route.access == "private" then "!private" else "";
          bearerTag = if route.bearerTokenFile != null then "!bearer=${route.bearerTokenFile}" else "";
          tailnetIdentityTag = if route.identifyTailnetUsers then "!tailnet-identity" else "";
        in
        "${hostname}=${route.upstreamAddress}${accessTag}${bearerTag}${tailnetIdentityTag}"
    ) hostProxyConfiguration.routes
  );
  identifiesTailnetUsers = lib.any (route: route.identifyTailnetUsers) (
    lib.attrValues hostProxyConfiguration.routes
  );
  certificatesSpecification = lib.concatStringsSep "," (
    map (
      certificate: "${certificate.certificateFile}:${certificate.privateKeyFile}"
    ) hostProxyConfiguration.certificates
  );
  serverConfiguration = pkgs.writeText "host-proxy-server.yaml" ''
    ---
    version: 1
    pid_file: /run/host-proxy/host-proxy.pid
    upgrade_sock: /run/host-proxy/upgrade.sock
  '';
in
{
  options.services.hostProxy = {
    enable = lib.mkEnableOption "the host reverse proxy on ports 80 and 443";

    routes = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            upstreamAddress = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                Address of the upstream server (host:port). Mutually exclusive
                with redirectTo; set exactly one per route.
              '';
            };
            redirectTo = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                Permanently redirect (301) requests for this hostname to
                https://<redirectTo><path>. The target is fixed configuration, so
                it cannot become an open redirect. TLS still terminates here, so a
                certificate covering this hostname is required. Mutually exclusive
                with upstreamAddress.
              '';
            };
            access = lib.mkOption {
              type = lib.types.enum [
                "public"
                "private"
              ];
              default = "public";
              description = ''
                Access control for a proxied route. Public routes are reachable by
                anyone. Private routes only accept connections from loopback,
                RFC 1918, and Tailscale CGNAT addresses. Ignored for redirects.
              '';
            };
            bearerTokenFile = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                Path to a file of accepted bearer tokens, one per line. When set,
                requests must carry a matching Authorization: Bearer header or
                receive a 401 without reaching the upstream. Listing several
                tokens allows rotation without downtime. `systemctl reload
                host-proxy` hands the listening sockets to a fresh process that
                re-reads the file, and SIGHUP re-reads it in place, so token
                changes take effect without dropping connections. Ignored for
                redirects.
              '';
            };
            identifyTailnetUsers = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Ask the local tailscaled which tailnet user each client is and
                pass it upstream in the X-Tailnet-User-Login and
                X-Tailnet-User-Name headers. Clients outside the tailnet, and
                lookups that fail, are forwarded without them. Every route strips
                those headers from client requests whether or not this is set, so
                the upstream can trust them. Off by default, so a host that never
                sets it never contacts tailscaled. Pair it with access = "private"
                so only tailnet clients reach the route at all.
              '';
            };
          };
        }
      );
      description = ''
        Map from hostname to route configuration. Matching is exact, so
        subdomains need their own entries. Requests for hosts not listed
        here receive a 404.
      '';
      example = {
        "example.org" = {
          upstreamAddress = "127.0.0.1:3000";
        };
        "admin.example.org" = {
          upstreamAddress = "127.0.0.1:4000";
          access = "private";
        };
      };
    };

    certificates = lib.mkOption {
      type = lib.types.listOf (
        lib.types.submodule {
          options = {
            certificateFile = lib.mkOption {
              type = lib.types.str;
              description = "Path to the PEM certificate file.";
            };
            privateKeyFile = lib.mkOption {
              type = lib.types.str;
              description = "Path to the PEM private key file.";
            };
          };
        }
      );
      description = ''
        TLS certificates to present on port 443. Pingora selects the
        correct certificate per connection using SNI. Each certificate
        should cover one or more hostnames listed in routes.
      '';
    };

    rateLimitPerSecond = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.positive;
      default = 100;
      description = ''
        Maximum requests per second accepted from a single client IP
        address before the proxy answers 429 without any routing or
        authentication work. Set to null to disable rate limiting.
      '';
    };

    tailscaledSocket = lib.mkOption {
      type = lib.types.str;
      default = "/run/tailscale/tailscaled.sock";
      description = ''
        The tailscaled socket that routes with identifyTailnetUsers ask.
      '';
    };

    metricsAddress = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "127.0.0.1:9184";
      description = ''
        Address (host:port) to serve Prometheus metrics on. The endpoint
        carries no authentication of its own, so bind it to loopback or a
        private interface. Null disables the metrics listener.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Open TCP ports 80 and 443 in the firewall.";
    };
  };

  config = lib.mkIf hostProxyConfiguration.enable {
    assertions =
      lib.mapAttrsToList (hostname: route: {
        assertion = (route.upstreamAddress != null) != (route.redirectTo != null);
        message = ''
          services.hostProxy.routes."${hostname}" must set exactly one of
          upstreamAddress or redirectTo.
        '';
      }) hostProxyConfiguration.routes
      ++ lib.mapAttrsToList (hostname: route: {
        assertion = route.bearerTokenFile == null || route.redirectTo == null;
        message = ''
          services.hostProxy.routes."${hostname}" sets bearerTokenFile on a
          redirect, which is never authenticated. Remove one of them.
        '';
      }) hostProxyConfiguration.routes
      ++ lib.mapAttrsToList (hostname: route: {
        assertion = !route.identifyTailnetUsers || route.redirectTo == null;
        message = ''
          services.hostProxy.routes."${hostname}" sets identifyTailnetUsers on a
          redirect, which has no upstream to tell. Remove one of them.
        '';
      }) hostProxyConfiguration.routes;

    users.users.host-proxy = {
      isSystemUser = true;
      group = "host-proxy";
    };
    users.groups.host-proxy = { };

    networking.firewall.allowedTCPPorts = lib.mkIf hostProxyConfiguration.openFirewall [
      80
      443
    ];

    systemd.services.host-proxy = {
      description = "Host reverse proxy";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      reloadIfChanged = true;

      environment = {
        HOST_PROXY_ROUTES = routesSpecification;
        HOST_PROXY_CERTIFICATES = certificatesSpecification;
        RUST_LOG = "info";
      }
      // lib.optionalAttrs (hostProxyConfiguration.rateLimitPerSecond != null) {
        HOST_PROXY_RATE_LIMIT_PER_SECOND = toString hostProxyConfiguration.rateLimitPerSecond;
      }
      // lib.optionalAttrs (hostProxyConfiguration.metricsAddress != null) {
        HOST_PROXY_METRICS_ADDRESS = hostProxyConfiguration.metricsAddress;
      }
      // lib.optionalAttrs identifiesTailnetUsers {
        HOST_PROXY_TAILSCALED_SOCKET = hostProxyConfiguration.tailscaledSocket;
      };

      serviceConfig = {
        Type = "forking";
        PIDFile = "/run/host-proxy/host-proxy.pid";
        RuntimeDirectory = "host-proxy";
        ExecStart = "${package}/bin/host-proxy --daemon --conf ${serverConfiguration}";
        ExecReload = [
          "${package}/bin/host-proxy --test --conf ${serverConfiguration}"
          "${pkgs.coreutils}/bin/kill -QUIT $MAINPID"
          "${package}/bin/host-proxy --upgrade --daemon --conf ${serverConfiguration}"
        ];
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
