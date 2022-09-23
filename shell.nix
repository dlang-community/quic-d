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
    ];

    shellHook = ''
      figlet "Welcome  to Quic-D"
    '';
  }
