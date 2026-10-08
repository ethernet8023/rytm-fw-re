{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    pkgsCross.m68k.buildPackages.gcc
    pkgsCross.m68k.buildPackages.binutils
    gnumake
  ];
}
