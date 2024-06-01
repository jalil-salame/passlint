{ lib, rustPlatform }:
let
  readToml = path: builtins.fromTOML (builtins.readFile path);
  cargoToml = readToml ./Cargo.toml;
  pname = cargoToml.package.name;
  inherit (cargoToml.package) version description;
in
rustPlatform.buildRustPackage {
  inherit pname version;
  src = builtins.path {
    path = ./.;
    name = "${pname}-source";
  };
  cargoLock.lockFile = ./Cargo.lock;
  useNextest = true;

  meta = {
    inherit description;
    license = lib.licenses.mit;
    homepage = "https://github.com/jalil-salame/passlint";
    mainProgram = "passlint";
  };
}
