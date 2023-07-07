#!/usr/bin/perl -w
use strict;
use v5.10;

use Storable qw/thaw/;
use JSON;

open my $fh, '<', shift or die $!;
my $frozen = do { local $/ = undef; <$fh> };
close $fh;
say encode_json thaw $frozen;