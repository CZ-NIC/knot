
with import <nixpkgs> {};

(callPackage ./. {
}).overrideAttrs (attrs: {
  src = ./knot-{{ version }}.tar.xz;
})

