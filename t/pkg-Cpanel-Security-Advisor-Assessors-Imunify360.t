#!/usr/local/cpanel/3rdparty/bin/perl

# Copyright 2018, cPanel, L.L.C.
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

use Cpanel::Version ();
use Test::Assessor  ();
use Test::More;
use Test::Deep;
use Test::MockModule;
use HTTP::Response;

use Cpanel::Security::Advisor::Assessors::Imunify360 ();

plan skip_all => 'Requires cPanel & WHM v80 or later' if Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.79' );

plan tests => 7;

my $mocked_version_module    = Test::MockModule->new('Cpanel::Version');
my $mocked_imunify360_module = Test::MockModule->new('Whostmgr::Imunify360');
my $mocked_HTTP              = Test::MockModule->new('Cpanel::HTTP::Client');

my $response_imunify_disabled = Cpanel::HTTP::Client::Response->new(
    {
        success => 1,
        status  => 200,
        content => '
            {
                "disabled": 1,
                "url": "",
                "email": ""
            }',
    }
);
$response_imunify_disabled->header( 'Content-Type', 'application/json' );

my $response_imunify_enabled = Cpanel::HTTP::Client::Response->new(
    {
        success => 1,
        status  => 200,
        content => '
            {
                "disabled": 0,
                "url": "",
                "email": ""
            }',
    }
);
$response_imunify_enabled->header( 'Content-Type', 'application/json' );

subtest 'When not running v80 or later' => sub {
    plan tests => 1;

    $mocked_version_module->redefine( getversionnumber => sub { '11.70' } );

    my $advice = get_advice();

    is_deeply( $advice, [], "Should not get advice for versions lower than 80" ) or diag explain $advice;
};

subtest 'When Imunify360 is disabled in Manage2' => sub {
    plan tests => 1;

    $mocked_version_module->redefine( getversionnumber => sub { '11.80' } );
    $mocked_HTTP->redefine( 'get' => sub { $response_imunify_disabled } );
    my $advice = get_advice();

    is_deeply( $advice, [], "Should not return the Imunify360 advice" ) or diag explain $advice;
};

subtest 'When Imunify360 is enabled in Manage2' => sub {
    plan tests => 1;

    $mocked_HTTP->redefine( 'get' => sub { $response_imunify_enabled } );
    my $advice = get_advice();

    ok( exists $advice->[0]->{'advice'}, "Should return the Imunify360 advice" );
};

$mocked_imunify360_module->redefine( is_imunify360_licensed  => sub { 0 } );
$mocked_imunify360_module->redefine( is_imunify360_installed => sub { 0 } );

subtest 'When Imunify360 is not installed or licensed' => sub {
    plan tests => 1;

    $mocked_imunify360_module->redefine( is_imunify360_licensed => sub { 0 } );

    my $advice   = get_advice();
    my $expected = [
        {
            'advice' => {
                'block_notify' => 1,
                'key'          => 'Imunify360_purchase',
                'suggestion'   => 'Imunify360 delivers sophisticated detection and display of security threats, powered by a self-learning firewall with herd immunity. It blocks attacks in real-time using a combination of technologies, including:
    <ul>
        <li>Proactive Defense™</li>
        <li>Smart Intrusion Detection and Protection System</li>
        <li>Malware Detection</li>
        
        <li>Patch Management via KernelCare</li>
        
        <li><a href="https://go.cpanel.net/buyimunify360" target="_new">Learn more about Imunify360</a></li>
    </ul>
Get Imunify360 (../scripts12/purchase_imunify360_init).
',
                'text' => 'Use Imunify360 for complete protection against attacks on your servers.',
                'type' => 4
            },
            'function' => '_suggest_imunify360',
            'module'   => 'Cpanel::Security::Advisor::Assessors::Imunify360'
        }
    ];

    cmp_deeply( $advice, $expected, "It should advice buying an Imunify360 license" ) or diag explain $advice;
};

subtest 'When has a license but Imunify360 is not installed' => sub {
    plan tests => 1;

    $mocked_imunify360_module->redefine( is_imunify360_licensed  => sub { 1 } );
    $mocked_imunify360_module->redefine( is_imunify360_installed => sub { 0 } );

    my $advice   = get_advice();
    my $expected = [
        {
            'advice' => {
                'block_notify' => 1,
                'key'          => 'Imunify360_install',
                'suggestion'   => 'Install Imunify360 (../scripts12/install_imunify360).',
                'text'         => 'You have an Imunify360 license, but you do not have Imunify360 installed on your server.',
                'type'         => 4
            },
            'function' => '_suggest_imunify360',
            'module'   => 'Cpanel::Security::Advisor::Assessors::Imunify360'
        }
    ];

    cmp_deeply( $advice, $expected, "It should advice to install Imunify360" ) or diag explain $advice;
};

subtest 'When Imunify360 is installed but not licensed' => sub {
    plan tests => 1;

    $mocked_imunify360_module->redefine( is_imunify360_licensed  => sub { 0 } );
    $mocked_imunify360_module->redefine( is_imunify360_installed => sub { 1 } );

    my $advice   = get_advice();
    my $expected = [
        {
            'advice' => {
                'block_notify' => 1,
                'key'          => 'Imunify360_update_license',
                'suggestion'   => '<style>
#Imunify360_update_license blockquote {
    margin:0
}
</style>
<ul>
    <li>To purchase a license, visit the cPanel Store (../scripts12/purchase_imunify360_init).    </li>
    <li>To uninstall Imunify360, read the Imunify360 Documentation (https://docs.imunify360.com/uninstall/).    </li>
</ul>
',
                'text' => 'Imunify360 is installed but you do not have a current license.',
                'type' => 4
            },
            'function' => '_suggest_imunify360',
            'module'   => 'Cpanel::Security::Advisor::Assessors::Imunify360'
        }
    ];

    cmp_deeply( $advice, $expected, "It should advice to renew the license" ) or diag explain $advice;
};

subtest 'When Imunify360 is installed and licensed' => sub {
    plan tests => 1;

    $mocked_imunify360_module->redefine( is_imunify360_licensed  => sub { 1 } );
    $mocked_imunify360_module->redefine( is_imunify360_installed => sub { 1 } );

    my $advice   = get_advice();
    my $expected = [
        {
            'advice' => {
                'block_notify' => 1,
                'key'          => 'Imunify360_present',
                'suggestion'   => 'Open Imunify360 (..//cgi/imunify/handlers/index.cgi#/admin/dashboard/incidents).',
                'text'         => 'Your server is protected by Imunify360. For help getting started, read Imunify360’s documentation (https://www.imunify360.com/getting-started).',
                'type'         => 1
            },
            'function' => '_suggest_imunify360',
            'module'   => 'Cpanel::Security::Advisor::Assessors::Imunify360'
        }
    ];

    cmp_deeply( $advice, $expected, "It should say that the server is protected" ) or diag explain $advice;
};

sub get_advice {
    my $object = Test::Assessor->new( assessor => 'Imunify360' );
    $object->generate_advice();
    my $advice = $object->get_advice();

    return $advice;
}
