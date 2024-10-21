{
  description = "secp256k1";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        erlang = pkgs.beam.interpreters.erlang_27;
        beamPkgs = pkgs.beam.packagesWith erlang;
        elixir = beamPkgs.elixir_1_17;
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [ pkgs.autoreconfHook ];

          buildInputs = [
            elixir
            pkgs.git
          ];

          env = {
            ERL_AFLAGS = "+pc unicode -kernel shell_history enabled";
            ELIXIR_ERL_OPTIONS = "+sssdio 128";
          };
        };
      }
    );
}
