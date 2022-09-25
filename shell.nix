{pkgs ? import <nixpkgs> {}}:
with pkgs;
  mkShell {
    buildInputs = [
      figlet

      dmd
      ldc
      dub

      openssl_3
      pkg-config

      curlHTTP3
    ];

    shellHook = ''
      figlet "Welcome  to Quic-D"
    '';
  }
