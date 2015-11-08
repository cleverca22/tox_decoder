with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "toxcore_plugin";
  src = ./.;
  #shark = /home/clever/wireshark-1.12.7;
  shark = "/nix/store/yy4l5hs8l8j0nakqsri85cirxh7mfjri-wireshark-1.12.7";
  glib = glib;
  buildInputs = [ glib ];
  postConfigure = ''
    ''${shark}/tools/make-dissector-reg . plugin toxcore.c
  '';
}