#!/usr/local/cpanel/3rdparty/bin/perl

# Copyright (c) 2021, cPanel, L.L.C.
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
use Test::Deep;
use Test::MockModule 'strict';

use Test::Assessor ();

use Cpanel::Exception ();
use Cpanel::Locale    ();
use Cpanel::Version   ();

use Cpanel::Security::Advisor                   ();
use Cpanel::Security::Advisor::Assessors        ();
use Cpanel::Security::Advisor::Assessors::_Self ();

plan skip_all => 'Requires cPanel & WHM v66 or later' if Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.65' );
plan tests    => 4;

# Suppress warning from base_path():
$ENV{'REQUEST_URI'} = '';

can_ok( 'Cpanel::Security::Advisor::Assessors::_Self', qw(version generate_advice) );

# Mock for Cpanel::FindBin::findbin:
my $mock_findbin = Test::MockModule->new('Cpanel::FindBin');
$mock_findbin->redefine( findbin => '/usr/bin/rpm' );

subtest 'RPM times out' => sub {
    plan tests => 1;

    # Mock for `rpm -qa` for when the program times out.
    my $mock_saferun = Test::MockModule->new('Cpanel::SafeRun::Full');
    $mock_saferun->redefine(
        run => sub {
            return {
                'did_dump_core'    => 0,
                'died_from_signal' => 15,
                'exit_value'       => 0,
                'message'          => 'Executed /usr/bin/rpm -qa --queryformat %{NAME} %{VERSION}-%{RELEASE}\\n',
                'status'           => 1,
                'stderr'           => '',
                'stdout'           => '',
                'timeout'          => 1,
            };
        }
    );
    my $expected = {
        'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
        'key'        => 'RPM_timed_out',
        'text'       => Cpanel::Locale::lh()->maketext('Security Advisor timed out while reading the RPM database of packages.'),
        'suggestion' =>
          Cpanel::Locale::lh()->maketext( "Security Advisor may include inaccurate results until it can fully read the RPM database. To resolve this, reduce the load on your system and then rebuild the RPM database with the following interface: [output,url,_1,Rebuild RPM Database,_2,_3].", Cpanel::Security::Advisor::Assessors->base_path('scripts/dialog?dialog=rebuildrpmdb'), 'target', '_blank' ),
        'block_notify' => 1,
    };
    cmp_assessor( '_Self', [$expected], 'Error displayed' );
};

subtest 'RPM crashes' => sub {
    plan tests => 1;

    # Mock for `rpm -qa` for when the program dies abnormally.
    my $mock_saferun = Test::MockModule->new('Cpanel::SafeRun::Full');
    $mock_saferun->redefine(
        run => sub {
            return {
                'did_dump_core'    => 0,
                'died_from_signal' => 6,
                'exit_value'       => 0,
                'message'          => 'Executed /usr/bin/rpm -qa --queryformat %{NAME} %{VERSION}-%{RELEASE}\\n',
                'status'           => 1,
                'stderr'           => '',
                'stdout'           => '',
                'timeout'          => undef,
            };
        }
    );
    my $expected = {
        'type'         => $Cpanel::Security::Advisor::ADVISE_BAD,
        'key'          => 'RPM_broken',
        'text'         => Cpanel::Locale::lh()->maketext('Security Advisor detected RPM database corruption.'),
        'suggestion'   => Cpanel::Locale::lh()->maketext( "Security Advisor may include inaccurate results until it can cleanly read the RPM database. To resolve this, rebuild the RPM database with the following interface: [output,url,_1,Rebuild RPM Database,_2,_3].", Cpanel::Security::Advisor::Assessors->base_path('scripts/dialog?dialog=rebuildrpmdb'), 'target', '_blank' ),
        'block_notify' => 1,
    };
    cmp_assessor( '_Self', [$expected], 'Error displayed' );
};

subtest 'RPM is incomplete' => sub {
    plan tests => 1;

    my $mock_saferun = Test::MockModule->new('Cpanel::SafeRun::Full');
    $mock_saferun->redefine(
        run => sub {
            return {
                'did_dump_core'    => 0,
                'died_from_signal' => 0,
                'exit_value'       => 0,
                'message'          => 'Executed /usr/bin/rpm -qa --queryformat %{NAME} %{VERSION}-%{RELEASE}\\n',
                'status'           => 1,
                'stderr'           => '',
                'stdout'           => "pkg-1.0-1.el7.x86_64\n" x 500,
                'timeout'          => undef,
            };
        }
    );
    my $expected = {
        'type'         => $Cpanel::Security::Advisor::ADVISE_WARN,
        'key'          => 'RPM_too_few',
        'text'         => Cpanel::Locale::lh()->maketext('The RPM database is smaller than expected.'),
        'suggestion'   => Cpanel::Locale::lh()->maketext("Security Advisor may include inaccurate results if the RPM database of packages is incomplete. To resolve this, check the cPanel update logs for RPM issues."),
        'block_notify' => 1,
    };
    cmp_assessor( '_Self', [$expected], 'Error displayed' );
};

sub cmp_assessor {
    my ( $assessor, $expected_advice, $msg ) = @_;

    local $Test::Builder::Level = $Test::Builder::Level + 1;

    my $object = Test::Assessor->new( assessor => $assessor );
    $object->generate_advice();

    my $got = $object->get_advice();
    $object->clear_advice();

    my @expected = map { { module => "Cpanel::Security::Advisor::Assessors::$assessor", function => ignore(), advice => $_ } } @$expected_advice;

    my $ret = cmp_deeply( $got, \@expected, $msg );
    diag explain $got if !$ret;

    return $ret;
}
