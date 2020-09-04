#!/usr/local/cpanel/3rdparty/bin/perl

# Copyright (c) 2020, cPanel, L.L.C.
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
use Test::Exception;

use Test::Mock::SecurityAdvisor;

use Cpanel::Version ();

use Cpanel::Security::Advisor ();

plan skip_all => 'Requires cPanel & WHM v86 or later' if Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.85' );
plan tests    => 4;

can_ok( 'Cpanel::Security::Advisor', qw(new generate_advice add_advice) );

subtest 'happy path' => sub {
    plan tests => 3;

    my $mock = Test::Mock::SecurityAdvisor->new();
    $mock->mock_all();

    my $advisor = $mock->new_advisor_object();
    lives_ok { $advisor->generate_advice() } 'generate_advice() lives in the happy path.';

    my $advisor_messages = $mock->get_advisor_messages();

    my @expected_msgs = map {
        {
            'channel' => 'securityadvisor',
            'data'    => $_,
        }
    } (
        {
            'module'  => 'Cpanel::Security::Advisor::Assessors::MockAssessor',
            'runtime' => 1,
            'state'   => 1,
            'type'    => 'mod_load'
        },
        {
            'state' => 0,
            'type'  => 'scan_run'
        },
        {
            'module'  => 'Cpanel::Security::Advisor::Assessors::MockAssessor',
            'state'   => 0,
            'type'    => 'mod_run',
            'version' => '9.99'
        },
        {
            'advice' => {
                'key'        => 'example_good_advice',
                'suggestion' => 'A suggestion.',
                'text'       => 'This is good.',
                'type'       => 1
            },
            'function' => 'generate_advice',
            'module'   => 'Cpanel::Security::Advisor::Assessors::MockAssessor',
            'type'     => 'mod_advice'
        },
        {
            'advice' => {
                'key'        => 'example_info_advice',
                'suggestion' => 'A suggestion.',
                'text'       => 'This is info.',
                'type'       => 2
            },
            'function' => 'generate_advice',
            'module'   => 'Cpanel::Security::Advisor::Assessors::MockAssessor',
            'type'     => 'mod_advice'
        },
        {
            'advice' => {
                'key'        => 'example_warn_advice',
                'suggestion' => 'A suggestion.',
                'text'       => 'This is a warning.',
                'type'       => 4
            },
            'function' => 'generate_advice',
            'module'   => 'Cpanel::Security::Advisor::Assessors::MockAssessor',
            'type'     => 'mod_advice'
        },
        {
            'advice' => {
                'key'        => 'example_bad_advice',
                'suggestion' => 'A suggestion.',
                'text'       => 'This is bad.',
                'type'       => 8
            },
            'function' => 'generate_advice',
            'module'   => 'Cpanel::Security::Advisor::Assessors::MockAssessor',
            'type'     => 'mod_advice'
        },
        {
            'message' => '',
            'module'  => 'Cpanel::Security::Advisor::Assessors::MockAssessor',
            'state'   => 1,
            'type'    => 'mod_run',
            'version' => '9.99'
        },
        {
            'state' => 1,
            'type'  => 'scan_run'
        }
    );

    cmp_deeply( $advisor_messages, \@expected_msgs, 'Got expected messages in the happy path.' ) or diag explain $advisor_messages;

    my $logged_warnings = $mock->get_func_calls( 'Cpanel::Logger', 'warn' );

    cmp_deeply( $logged_warnings, [], 'No logged warnings in the happy path.' ) or diag explain $logged_warnings;

    return;
};

subtest 'handle module load exception' => sub {
    plan tests => 4;

    my $mock = Test::Mock::SecurityAdvisor->new();
    $mock->mock_all();

    $mock->set_assessor_module('Cpanel::Security::Advisor::Assessors::MockLoadFail');

    my $advisor;
    lives_ok { $advisor = $mock->new_advisor_object() } 'new() lives when there is a module load exception.';
    lives_ok { $advisor->generate_advice() } 'generate_advice() lives when there is a module load exception.';

    my @expected_msgs = map {
        {
            'channel' => 'securityadvisor',
            'data'    => $_,
        }
    } (
        {
            'message' => re('The system failed to load the module'),
            'module'  => 'Cpanel::Security::Advisor::Assessors::MockLoadFail',
            'state'   => 0,
            'type'    => 'mod_load'
        },
        {
            'state' => 0,
            'type'  => 'scan_run'
        },
        {
            'state' => 1,
            'type'  => 'scan_run'
        }
    );

    my $advisor_messages = $mock->get_advisor_messages();
    cmp_deeply( $advisor_messages, \@expected_msgs, 'Got expected messages when there is a module new exception.' ) or diag explain $advisor_messages;

    my $logged_warnings = $mock->get_func_calls( 'Cpanel::Logger', 'warn' );
    cmp_deeply(
        $logged_warnings,
        [
            [ isa('Cpanel::Logger'), re('The system failed to load the module') ],
        ],
        'Got expected logged warnings when there is a module load exception.'
    ) or diag explain $logged_warnings;

    return;
};

subtest 'handle assessor->new() exception' => sub {
    plan tests => 4;

    my $mock = Test::Mock::SecurityAdvisor->new();
    $mock->mock_all();

    $mock->set_assessor_module('Cpanel::Security::Advisor::Assessors::MockNewFail');

    my $advisor;
    lives_ok { $advisor = $mock->new_advisor_object() } 'new() lives when there is an assessor->new() exception.';
    lives_ok { $advisor->generate_advice() } 'generate_advice() lives when there is an assessor->new() exception.';

    my @expected_msgs = map {
        {
            'channel' => 'securityadvisor',
            'data'    => $_,
        }
    } (
        {
            'message' => re('No new for you!'),
            'module'  => 'Cpanel::Security::Advisor::Assessors::MockNewFail',
            'state'   => 0,
            'type'    => 'mod_load'
        },
        {
            'state' => 0,
            'type'  => 'scan_run'
        },
        {
            'state' => 1,
            'type'  => 'scan_run'
        }
    );

    my $advisor_messages = $mock->get_advisor_messages();
    cmp_deeply( $advisor_messages, \@expected_msgs, 'Got expected messages when there is an assessor->new() exception.' ) or diag explain $advisor_messages;

    my $logged_warnings = $mock->get_func_calls( 'Cpanel::Logger', 'warn' );
    cmp_deeply(
        $logged_warnings,
        [
            [ isa('Cpanel::Logger'), re('No new for you!') ],
        ],
        'Got expected logged warnings when there is an assessor->new() exception.'
    ) or diag explain $logged_warnings;

    return;
};
