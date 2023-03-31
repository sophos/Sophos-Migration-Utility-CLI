#!/usr/bin/perl
#Copyright Sophos Ltd 2023
#
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use v5.10;
use strict;
use warnings;

use Storable;
use Data::Dumper;
use JSON ();

binmode STDOUT, ':encoding(utf8)';

usage() if (@ARGV != 1) || (! -f $ARGV[0]);

sub usage {
	die "$0 /path/to/snapshot\n"
}

sub read_backup {
    my ($fn) = @_;
    -f $fn or die $!;
    retrieve $fn
}

sub make_json {
    my ($backup) = @_;
    my $json = JSON->new->pretty;
    $json->encode($backup)
}

my $backup = read_backup shift;
say make_json $backup
