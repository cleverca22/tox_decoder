with import ~/nixpkgs {};

stdenv.mkDerivation {
  name = "toxcore_plugin";
  src = lib.cleanSource ./src;
  nativeBuildInputs = [ pkgconfig ];
  buildInputs = [ glib libsodium wireshark ];
}
