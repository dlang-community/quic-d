# QUIC-D

[![dub][dub-badge]][dub]
[![CI][gh-actions-status]][gh-actions]
[![codecov][codecov-status]][codecov]

`quic-d` is an implementation of the [QUIC][quic] protocol in [Dlang][dlang].

## Development environment

### Dependencies

* D compiler
* Dub
* OpenSSL >= 3.0.5

The dependencies above can either be installed manually (in any way you prefer)
or automatically via Nix.

### Nix

This project uses a [Nix][nix]_[Flake][nix-flakes]-based [development
shell][nix-development-shell] to specify the complete list of dependencies and
precisely pin their versions.  Note that this includes programs and libraries
like the DMD and LDC D compilers, OpenSSL, and cURL, however D library
dependencies are still managed by [Dub][dub-pm] (a future integration between
Dub and Nix may allow Nix to manage all dependencies).

### Getting started

#### Enter the dev shell

1. [Install][nix-install] the Nix package manager.
2. [Enable][nix-flakes-enable] flakes.
3. Optionally, install and enable Direnv, see [below](#direnv).
4. Clone the project and enter the repo:

    `git clone https://github.com/dlang-community/quic-d && cd quic-d`

5. At this point, if you have direnv enabled (as specified in step 3), the Nix
  development shell should have been automatically activated. If you, however,
  skipped this step, you will need to manually enter the shell like so:

    `nix develop`

#### Build the project and run the test suite

Assuming you have already entered the dev shell, you can use standard Dub commands to work on the project

1. Building the project:

    `dub build`

2. Running the test suite:

    `dub test`

### Direnv

For additional convenience, we recommend using [Direnv][direnv], so that the
development shell will get automatically activated without the need for running
`nix develop` each time one wants to work on the project.

#### Setup direnv

1. Install direnv

    `nix-env -iA nixpkgs.direnv`

2. [Hook][direnv-hook] direnv to your shell.

3. Allow direnv to be used when inside the `quic-d` repo:

    `direnv allow .`
    (replace `.` with the location of the repo on your computer if needed)

#### How it works

This repo contains an `.envrc` file which includes an integration between `nix
develop` and direnv (implemented by [nix-direnv][nix-direnv]). The way this
works from user's perspective is that each time you `cd` (or `pushd`) into the
repo folder (or any nested dir), direnv will detect that and load the nearest
`.envrc` file. Then the `.envrc` file in this repo will activate the nix dev
shell in a subshell and then carry-over the environment variables to the current
shell. This only works if direnv is integrated with the current shell of the
user and if they have allowed the repo's `.envrc` file to be loaded (this is
opt-in for security reasons.)

[quic]: https://datatracker.ietf.org/doc/rfc9000/

[nix]: https://nixos.org/
[nix-install]: https://nixos.org/download.html
[nix-flakes]: https://www.tweag.io/blog/2020-05-25-flakes/
[nix-flakes-enable]: https://nixos.wiki/wiki/Flakes#Enable_flakes
[nix-development-shell]: https://nix.dev/tutorials/ad-hoc-developer-environments#ad-hoc-envs
[direnv]: https://direnv.net/
[direnv-hook]: https://direnv.net/docs/hook.html
[nix-direnv]: https://github.com/nix-community/nix-direnv

[dlang]: https://dlang.org/
[dub-pm]: https://dlang.org/

[dub]: https://code.dlang.org/packages/quic-d
[dub-badge]: https://img.shields.io/dub/v/quic-d

[codecov]: https://codecov.io/github/dlang-community/quic-d
[codecov-status]: https://codecov.io/github/dlang-community/quic-d/branch/main/graph/badge.svg?token=U7ZXz8M8gj

[gh-actions]: https://github.com/dlang-community/quic-d/actions
[gh-actions-status]: https://github.com/dlang-community/quic-d/actions/workflows/ci.yml/badge.svg
