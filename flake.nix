{
  description = "Host-level reverse proxy routing public domains to local services";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
      flake-utils,
    }:
    {
      nixosModules.default = import ./nix/module.nix self;
    }
    // flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable."1.94.0".default;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;

          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.cmake
            pkgs.perl
          ];

          buildInputs = [
            pkgs.openssl
            pkgs.zstd
          ];

          ZSTD_SYS_USE_PKG_CONFIG = "1";
        };

        cargoArtifacts = craneLib.buildDepsOnly (
          commonArgs
          // {
            pname = "host-proxy-deps";
            version = "0.3.0";
          }
        );

        hostProxyBuild = craneLib.buildPackage (
          commonArgs
          // {
            pname = "host-proxy";
            version = "0.3.0";
            inherit cargoArtifacts;
          }
        );
      in
      {
        packages.default = hostProxyBuild;

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            rustToolchain
            pkgs.pkg-config
            pkgs.cmake
            pkgs.perl
          ];

          buildInputs = [
            pkgs.openssl
            pkgs.zstd
          ];

          ZSTD_SYS_USE_PKG_CONFIG = "1";
        };
      }
    );
}
