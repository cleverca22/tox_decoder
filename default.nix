with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "toxcore_plugin";
  src = ./.;
  shark = /home/clever/x/wireshark-2.2.0;
  glib = glib.out;
  glibdev = glib.dev;
  buildInputs = [ glib libsodium python ];
  postConfigure = ''
    ''${shark}/tools/make-dissector-reg.py . plugin toxcore.c
  '';
}