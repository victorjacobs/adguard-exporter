{
  buildGoModule,
  lib,
}:

buildGoModule {
  pname = "adguard-exporter";
  version = "unstable";

  src = lib.cleanSource ../.;

  vendorHash = "sha256-EwRUlc8tMlfHFqqQTs69y7p2yRhSeM6a9zLKtSW5r44=";

  meta = {
    description = "Prometheus exporter for AdGuard Home";
    homepage = "https://github.com/victorjacobs/adguard-exporter";
    mainProgram = "adguard-exporter";
  };
}
