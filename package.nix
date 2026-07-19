{
  buildGoModule,
  lib,
}:

buildGoModule {
  pname = "adguard-exporter";
  version = "unstable";

  src = lib.cleanSource ./.;

  vendorHash = "sha256-oeCSKwDKVwvYQ1fjXXTwQSXNl/upDE3WAAk680vqh3U=";

  meta = {
    description = "Prometheus exporter for AdGuard Home";
    homepage = "https://github.com/victorjacobs/adguard-exporter";
    mainProgram = "adguard-exporter";
  };
}
