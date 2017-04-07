#!/usr/local/cpanel/3rdparty/bin/perl

# Copyright (c) 2017, cPanel, Inc.
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
# DISCLAIMED. IN NO EVENT SHALL  BE LIABLE FOR ANY
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
use Test::MockModule;

use Test::Assessor ();

use Cpanel::Exception ();
use Cpanel::Version   ();

plan skip_all => 'Requires cPanel & WHM v66 or later' if Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.65' );
plan tests => 4;

my $kernel_status = Test::MockModule->new('Cpanel::Kernel::Status');
$kernel_status->mock(
    kernel_status => sub {
        return {
            has_kernelcare   => 0,
            running_version  => '3.10.0-514.el7.x86_64',
            boot_version     => '3.10.0-514.el7.x86_64',
            reboot_required  => 0,
            update_available => undef,
            running_latest   => 1,
        };
    },
);
my $expected_kernel_status = {
    key  => 'Kernel_running_is_current',
    text => 'The system kernel is up-to-date at version “3.10.0-514.el7.x86_64”.',
    type => $Cpanel::Security::Advisor::ADVISE_GOOD,
};

subtest 'No advertisement when it won’t help the system' => sub {
    plan tests => 2;

    my $KC = Test::MockModule->new('Cpanel::KernelCare');
    $KC->mock( system_has_kernelcare => sub { 1 } );

    cmp_assessor( 'Kernel', [$expected_kernel_status], 'System already has KernelCare' );

    $KC->mock(
        system_has_kernelcare      => sub { 0 },
        system_supports_kernelcare => sub { 0 },
    );
    cmp_assessor( 'Kernel', [$expected_kernel_status], 'System doesn’t support KernelCare' );
};

subtest 'Handle advertisement when unable to reach server' => sub {
    plan tests => 4;

    my $KC = Test::MockModule->new('Cpanel::KernelCare');
    $KC->mock(
        system_has_kernelcare      => sub { 0 },
        system_supports_kernelcare => sub { 1 },
    );

    my $available = Test::MockModule->new('Cpanel::KernelCare::Availability');
    $available->mock(
        get_company_advertising_preferences => sub { die "Testing\n" },
    );

    my $expected = {
        key  => 'Kernel_kernelcare_preference_error',
        text => "The system cannot check the KernelCare promotion preferences: Testing\n",
        type => $Cpanel::Security::Advisor::ADVISE_WARN,
    };
    cmp_assessor( 'Kernel', [ $expected, $expected_kernel_status ], 'Handle unexpected error - string' );

    $available->mock(
        get_company_advertising_preferences => sub { die Cpanel::Exception->create('Object test') },
    );

    $expected->{text} = 'The system cannot check the KernelCare promotion preferences: Object test';
    cmp_assessor( 'Kernel', [ $expected, $expected_kernel_status ], 'Handle unexpected error - object' );

    $available->mock(
        get_company_advertising_preferences => sub { die Cpanel::Exception::create( 'HTTP::Server', [ method => 'get', content => '', status => 500, reason => '', url => '', headers => '', redirects => '' ] ) },
    );
    cmp_assessor( 'Kernel', [$expected_kernel_status], 'No message when server returns error' );

    $available->mock(
        get_company_advertising_preferences => sub { die Cpanel::Exception::create('HTTP::Network') },
        system_license_from_cpanel          => sub { },
    );

    $expected = {
        key          => 'Kernel_kernelcare_purchase',
        text         => 'Upgrade to KernelCare.',
        suggestion   => 'KernelCare provides an easy and effortless way to ensure that your operating system uses the most up-to-date kernel without the need to reboot your server. Upgrade to KernelCare (../scripts12/purchase_kernelcare_init).',
        type         => $Cpanel::Security::Advisor::ADVISE_WARN,
        block_notify => 1,                                                                                                                                                                                                                              # Because
    };
    cmp_assessor( 'Kernel', [ $expected, $expected_kernel_status ], 'Message displayed when local network is down' );
};

subtest 'Notify users of an existing license' => sub {
    plan tests => 3;

    my $KC = Test::MockModule->new('Cpanel::KernelCare');
    $KC->mock(
        system_has_kernelcare      => sub { 0 },
        system_supports_kernelcare => sub { 1 },
    );

    my $available = Test::MockModule->new('Cpanel::KernelCare::Availability');
    $available->mock(
        get_company_advertising_preferences => sub { { disabled => 0, url => '', email => '' } },
        system_license_from_cpanel          => sub { die "Testing\n" },
    );

    my $expected = {
        key  => 'Kernel_kernelcare_license_error',
        text => "The system cannot check for KernelCare licenses: Testing\n",
        type => $Cpanel::Security::Advisor::ADVISE_WARN,
    };
    cmp_assessor( 'Kernel', [ $expected, ignore(), $expected_kernel_status ], 'Handle error - string' );

    $available->mock(
        system_license_from_cpanel => sub { die Cpanel::Exception->create('Object test') },
    );

    $expected->{text} = 'The system cannot check for KernelCare licenses: Object test';
    cmp_assessor( 'Kernel', [ $expected, ignore(), $expected_kernel_status ], 'Handle error - object' );

    $available->mock(
        system_license_from_cpanel => sub { {} },    #Hashref would have data
    );

    my $promotion = 'KernelCare provides an easy and effortless way to ensure that your operating system uses the most up-to-date kernel without the need to reboot your server.';
    $expected = {
        key        => 'Kernel_kernelcare_valid_license_but_not_installed',
        text       => 'Valid KernelCare License Found, but KernelCare is Not Installed.',
        suggestion => "$promotion Click to install (../scripts12/purchase_kernelcare_completion?order_status=success).",
        type       => $Cpanel::Security::Advisor::ADVISE_BAD,
    };
    cmp_assessor( 'Kernel', [ $expected, $expected_kernel_status ], 'Display notice to install KernelCare' );
};

subtest 'Display stand-alone advertisement' => sub {
    plan tests => 5;

    my $KC = Test::MockModule->new('Cpanel::KernelCare');
    $KC->mock(
        system_has_kernelcare      => sub { 0 },
        system_supports_kernelcare => sub { 1 },
    );

    my $available = Test::MockModule->new('Cpanel::KernelCare::Availability');
    $available->mock(
        system_license_from_cpanel          => sub { },
        get_company_advertising_preferences => sub { { disabled => 1 } },
    );
    cmp_assessor( 'Kernel', [$expected_kernel_status], 'Don’t show advertisement when disabled' );

    $available->mock(
        get_company_advertising_preferences => sub { { disabled => 0, url => '', email => '' } },
    );

    my $promotion = 'KernelCare provides an easy and effortless way to ensure that your operating system uses the most up-to-date kernel without the need to reboot your server.';
    my $expected  = {
        key          => 'Kernel_kernelcare_purchase',
        text         => 'Upgrade to KernelCare.',
        suggestion   => "$promotion Upgrade to KernelCare (../scripts12/purchase_kernelcare_init).",
        type         => $Cpanel::Security::Advisor::ADVISE_WARN,
        block_notify => 1,                                                                             # Because
    };
    cmp_assessor( 'Kernel', [ $expected, $expected_kernel_status ], 'Default advertisement displayed' );

    $available->mock(
        get_company_advertising_preferences => sub { { disabled => 0, url => 'https://example.com', email => '' } },
    );

    $expected->{suggestion} = "$promotion Upgrade to KernelCare (https://example.com).";
    cmp_assessor( 'Kernel', [ $expected, $expected_kernel_status ], 'Custom advertisement displayed' );

    $available->mock(
        get_company_advertising_preferences => sub { { disabled => 0, url => 'https://example.com', email => 'user@example.com' } },
    );

    # $expected unchanged
    cmp_assessor( 'Kernel', [ $expected, $expected_kernel_status ], 'Custom advertisement displayed - overrides email' );

    $available->mock(
        get_company_advertising_preferences => sub { { disabled => 0, url => '', email => 'user@example.com' } },
    );

    $expected->{suggestion} = "$promotion For more information, email your provider (mailto:user\@example.com).";
    cmp_assessor( 'Kernel', [ $expected, $expected_kernel_status ], 'Email advertisement displayed' );
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
