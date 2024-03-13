#!/usr/bin/perl
#Copyright Sophos Ltd 2023
#
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use strict;
use warnings;
use Storable qw(thaw retrieve nstore);

my $fn = shift;

my $b;
if ($fn =~ /.abf/) {
    my $data = do {
        local $/ = undef;
        open my $fh, '<', $fn or die $!;
        <$fh>
    };
    $b = thaw $data;
} else {
    $b = retrieve $fn;
}

nstore $b, $fn . ".nstor"
