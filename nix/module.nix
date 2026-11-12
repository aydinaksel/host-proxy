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
          identifiedDigestLines = lib.concatLists (
            lib.mapAttrsToList (identity: digests: map (digest: "${digest} ${identity}") digests) (
              lib.optionalAttrs (route.bearerTokenDigestsByIdentity != null) route.bearerTokenDigestsByIdentity
            )
          );
          digestLines =
            lib.optionals (route.bearerTokenDigests != null) route.bearerTokenDigests ++ identifiedDigestLines;
          bearerTag =
            if digestLines != [ ] then
              "!bearer-sha256=${pkgs.writeText "host-proxy-${hostname}-bearer-token-digests" (lib.concatLines digestLines)}"
            else
              "";
          allowedPathsTag =
            if route.allowedPaths != null then "!paths=${lib.concatStringsSep "+" route.allowedPaths}" else "";
          identityHeaderTag =
            if route.identityHeader != null then "!identity-header=${route.identityHeader}" else "";
          tailnetIdentityTag = if route.identifyTailnetUsers then "!tailnet-identity" else "";
          clientNetworksTag =
            if route.allowedClientNetworks != null then
              "!networks=${lib.concatStringsSep "+" route.allowedClientNetworks}"
            else
              "";
        in
        "${hostname}=${route.upstreamAddress}${accessTag}${bearerTag}${tailnetIdentityTag}${clientNetworksTag}${allowedPathsTag}${identityHeaderTag}"
    ) hostProxyConfiguration.routes
  );
  tokenDigest = lib.types.strMatching "[0-9a-fA-F]{64}";
  tokenIdentityPattern = "[A-Za-z0-9._-]{1,150}";
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
            bearerTokenDigests = lib.mkOption {
              type = lib.types.nullOr (lib.types.nonEmptyListOf (lib.types.strMatching "[0-9a-fA-F]{64}"));
              default = null;
              example = [ "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" ];
              description = ''
                SHA-256 digests of the accepted bearer tokens, as 64-character
                hexadecimal strings. When set, requests must carry an
                Authorization: Bearer header whose token hashes to one of them,
                or receive a 401 without reaching the upstream. Only digests are
                configured, so they reveal no token and can live in public
                configuration. Compute one with `printf %s "$token" | sha256sum`.
                Listing several allows rotation without downtime, and a change
                takes effect through `systemctl reload host-proxy` without
                dropping connections. Ignored for redirects.
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
            allowedClientNetworks = lib.mkOption {
              type = lib.types.nullOr (lib.types.nonEmptyListOf lib.types.str);
              default = null;
              example = [
                "192.0.2.0/24"
                "2001:db8::/32"
              ];
              description = ''
                Networks, in address/prefix form, that may reach this route.
                Every other client gets a 403 before authentication or
                proxying. Null accepts any client the access setting allows.
                Suits a public route only a known service should call, such as
                a provider's published outbound ranges.
              '';
            };
            bearerTokenDigestsByIdentity = lib.mkOption {
              type = lib.types.nullOr (
                lib.types.attrsOf (
                  lib.types.coercedTo tokenDigest lib.toList (lib.types.nonEmptyListOf tokenDigest)
                )
              );
              default = null;
              example = {
                "fbrmarble.pan" = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
              };
              description = ''
                Accepted bearer tokens keyed by the identity each one stands for,
                as SHA-256 digests like bearerTokenDigests. An identity is made of
                letters, digits, '.', '_' and '-', at most 150 characters. Give an
                identity a list of digests to rotate its token without downtime.
                Combine with identityHeader to tell the upstream who is calling.
                Ignored for redirects.
              '';
            };
            identityHeader = lib.mkOption {
              type = lib.types.nullOr (lib.types.strMatching "[A-Za-z0-9-]+");
              default = null;
              example = "X-Scope-OrgID";
              description = ''
                Header that carries the identity of the presented token to the
                upstream, such as the X-Scope-OrgID tenant of Loki or Mimir. Any
                value the client sent in it is removed, so the upstream can trust
                it. Requires bearerTokenDigestsByIdentity, and then refuses
                tokens from bearerTokenDigests, which name no identity.
              '';
            };
            allowedPaths = lib.mkOption {
              type = lib.types.nullOr (lib.types.nonEmptyListOf (lib.types.strMatching "/[^,!+[:space:]]*"));
              default = null;
              example = [ "/loki/api/v1/push" ];
              description = ''
                Exact request paths this route forwards. Every other path gets a
                403 before authentication or proxying. The query string is not
                compared, and encoded or dot-segment variants of a path are
                refused rather than normalised. Suits an ingest route whose
                tokens must only reach the write endpoints of a store that also
                serves reads. Null forwards every path.
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
        assertion = route.bearerTokenDigests == null || route.redirectTo == null;
        message = ''
          services.hostProxy.routes."${hostname}" sets bearerTokenDigests on a
          redirect, which is never authenticated. Remove one of them.
        '';
      }) hostProxyConfiguration.routes
      ++ lib.mapAttrsToList (hostname: route: {
        assertion =
          route.identityHeader == null
          || (route.bearerTokenDigestsByIdentity != null && route.bearerTokenDigestsByIdentity != { });
        message = ''
          services.hostProxy.routes."${hostname}" sets identityHeader without any
          bearerTokenDigestsByIdentity, so there is no identity to pass upstream.
        '';
      }) hostProxyConfiguration.routes
      ++ lib.mapAttrsToList (hostname: route: {
        assertion = route.identityHeader == null || route.bearerTokenDigests == null;
        message = ''
          services.hostProxy.routes."${hostname}" sets identityHeader alongside
          bearerTokenDigests, whose tokens name no identity and would be refused.
          Move them into bearerTokenDigestsByIdentity.
        '';
      }) hostProxyConfiguration.routes
      ++ lib.mapAttrsToList (hostname: route: {
        assertion = lib.all (identity: builtins.match tokenIdentityPattern identity != null) (
          lib.attrNames (
            lib.optionalAttrs (route.bearerTokenDigestsByIdentity != null) route.bearerTokenDigestsByIdentity
          )
        );
        message = ''
          services.hostProxy.routes."${hostname}".bearerTokenDigestsByIdentity
          has an identity that is not 1 to 150 letters, digits, '.', '_' or '-'.
        '';
      }) hostProxyConfiguration.routes
      ++ lib.mapAttrsToList (hostname: route: {
        assertion =
          route.redirectTo == null
          || (route.bearerTokenDigestsByIdentity == null && route.allowedPaths == null);
        message = ''
          services.hostProxy.routes."${hostname}" sets bearerTokenDigestsByIdentity
          or allowedPaths on a redirect, which never reaches an upstream.
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
