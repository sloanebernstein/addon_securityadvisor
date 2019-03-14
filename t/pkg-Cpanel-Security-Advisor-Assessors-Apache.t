#!/usr/local/cpanel/3rdparty/bin/perl

# Copyright (c) 2018, cPanel, L.L.C.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the owner nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL cPanel, L.L.C. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib", "$FindBin::Bin/../pkg";

use Test::More;
use Cpanel::Version       ();
use Cpanel::Version::Tiny ();

plan skip_all => 'Requires cPanel & WHM v66 or later' if Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.65' );
plan tests => 4;

use Cpanel::Security::Advisor::Assessors::Apache ();

my %doesnot_doea3 = (
    75 => 0,
    76 => 0,
    77 => 1,
    78 => 1,
);

for my $v (qw(75 76 77 78)) {
    local $Cpanel::Version::Tiny::major_version = $v;

    my @calls;
    no warnings "redefine";
    local *Cpanel::Security::Advisor::Assessors::Apache::_check_for_easyapache3_eol    = sub { push @calls, '_check_for_easyapache3_eol' };
    local *Cpanel::Security::Advisor::Assessors::Apache::_check_for_apache_chroot      = sub { push @calls, '_check_for_apache_chroot' };
    local *Cpanel::Security::Advisor::Assessors::Apache::_check_for_easyapache_build   = sub { push @calls, '_check_for_easyapache_build' };
    local *Cpanel::Security::Advisor::Assessors::Apache::_check_for_eol_apache         = sub { push @calls, '_check_for_eol_apache' };
    local *Cpanel::Security::Advisor::Assessors::Apache::_check_for_symlink_protection = sub { push @calls, '_check_for_symlink_protection' };

    Cpanel::Security::Advisor::Assessors::Apache->generate_advice();

    if ( $doesnot_doea3{$v} ) {
        is_deeply \@calls, [ '_check_for_apache_chroot', '_check_for_symlink_protection' ], "v$v does not do ea3 specific checks";
    }
    else {
        is_deeply \@calls, [ '_check_for_easyapache3_eol', '_check_for_apache_chroot', '_check_for_easyapache_build', '_check_for_eol_apache', '_check_for_symlink_protection' ], "v$v does do ea3 specific checks";
    }
}
