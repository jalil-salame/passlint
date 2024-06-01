{
  description = "A linter for your password-store passwords";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      supportedSystems = [
        "x86_64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
      ];
      forEachSupportedSystem =
        f:
        lib.genAttrs supportedSystems (
          system:
          f {
            inherit system;
            pkgs = nixpkgs.legacyPackages.${system};
          }
        );
    in
    {
      # Nix code formatter; I like alejandra, but nixpkgsfmt, nixfmt-classic, and nixfmt-rfc-style also exist
      formatter = forEachSupportedSystem ({ pkgs, ... }: pkgs.nixfmt-rfc-style);

      # Packages exported by this flake
      packages = forEachSupportedSystem (
        { pkgs, ... }:
        let
          passlint = pkgs.callPackage ./default.nix { };
        in
        {
          inherit passlint;
          default = passlint;
        }
      );

      devShells = forEachSupportedSystem (
        { pkgs, ... }:
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cargo-flamegraph
              pkgs.cargo-hack
              pkgs.mold
              pkgs.openssl.dev
              pkgs.pkg-config
            ];
            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
            LD_LIBRARY_PATH = lib.makeLibraryPath [ pkgs.openssl ];
          };
        }
      );
    };
}
