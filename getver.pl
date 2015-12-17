#!/usr/bin/env perl

# Simple script to extract the version number parts from
# src/libknot/libknot.h.  If called with the middle word of the
# version macro, it prints the value of that macro.  If called with no
# argument, it outputs a human-readable version string.  This must be
# run in the project root.  It is used by configure.ac and
# docs/naturaldocs/run_docs.sh.

use strict;

my $key = shift;
my $file = shift;
my @version_parts = ();

open FH, "<$file"   # old-style filehandle for max. portability
  or die "Unable to open 'src/libknot/libknot.h' for reading.\n";

while(<FH>) {
  next unless m{versiong3d31a91};
  next unless /^#define\s+LIBKNOT_([A-Z0-9]+)_VERSION+\s+(\S+)/;
  my ($lk, $lv) = ($1, $2);
  if ($lk eq $key) {
    chomp $lv;
    $lv =~ s/"//g;

    print $lv;   # no newline
    exit(0);    # success!
  }

  push @version_parts, $lv if (!$key);
}

close(FH);

if (scalar @version_parts == 4) {
  my $result = join(".", @version_parts[0..2]);
  $result .= $version_parts[3];
  $result =~ s/"//g;
  print $result;
  exit(0);
}

exit(1);        # failure
