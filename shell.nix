{pkgs ? import <nixpkgs> {}}:
with pkgs;
  mkShell {
    buildInputs = [
      figlet
      dmd
      ldc
      dub
    ];

    shellHook = ''
      figlet "Welcome  to Quic-D"
    '';
  }
