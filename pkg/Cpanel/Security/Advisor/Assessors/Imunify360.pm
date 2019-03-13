package Cpanel::Security::Advisor::Assessors::Imunify360;

# Copyright (c) 2019, cPanel, L.L.C.
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
use base 'Cpanel::Security::Advisor::Assessors';

use Cpanel::Config::Sources ();
use Cpanel::Version         ();
use Cpanel::HTTP::Client    ();
use Cpanel::JSON            ();
use Cpanel::Sys::OS::Check  ();
use Cpanel::Sys::GetOS      ();
use Whostmgr::Imunify360    ();

use Cpanel::Imports;

our $IMUNIFY360_MINIMUM_CPWHM_VERSION = '11.79';    # we want it usable on both development and release builds for 11.80

sub version {
    return '1.00';
}

sub generate_advice {
    my ($self) = @_;
    my $is_imunify360_disabled = _get_imunify360_data()->{'disabled'};

    eval {
        if (   Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '>=', $IMUNIFY360_MINIMUM_CPWHM_VERSION )
            && _is_imunify360_supported()
            && !$is_imunify360_disabled ) {
            $self->_suggest_imunify360;
        }
    };
    if ( my $exception = $@ ) {
        print STDERR $exception;    # STDERR gets sent to ULC/logs/error_log.
        die $exception;
    }

    return 1;
}

sub _get_imunify360_data {
    my ($self) = @_;

    my $url = 'https://manage2.cpanel.net/imunify360.cgi';

    local $@;
    my $raw_resp = eval {
        my $http = Cpanel::HTTP::Client->new( timeout => 10 )->die_on_http_error();
        $http->get($url);
    };

    # on error
    return { disabled => 0, url => '', email => '' } if $@ or not $raw_resp;

    my $json_resp;
    if ( $raw_resp->{'success'} ) {
        eval { $json_resp = Cpanel::JSON::Load( $raw_resp->{'content'} ) };

        if ($@) {
            print STDERR $@;
            $json_resp = { disabled => 0, url => '', email => '' };
        }
    }
    else {
        $json_resp = { disabled => 0, url => '', email => '' };
    }

    return $json_resp;
}

sub _suggest_imunify360 {
    my ($self) = @_;

    if ( !Whostmgr::Imunify360::is_imunify360_licensed() && Whostmgr::Imunify360::is_imunify360_installed() ) {

        my $uninstall_docs_link = locale()->maketext( '[output,url,_1,Imunify360 Documentation,_2,_3].', 'https://docs.imunify360.com/uninstall/', 'target', '_blank' );
        my $store_link = locale()->maketext( '[output,url,_1,cPanel Store,_2,_3].', $self->base_path('scripts12/purchase_imunify360_init'), 'target', '_parent' );

        $self->add_warn_advice(
            key          => 'Imunify360_update_license',
            text         => locale()->maketext('You have [asis,Imunify360] installed but the license has expired.'),
            suggestion   => locale()->maketext('For updating the license go to the ') . $store_link . '<br /><br />' . locale()->maketext('For uninstalling go to the ') . $uninstall_docs_link,
            block_notify => 1,                                                                                                                                                                                                                                                                                                                 # Do not send a notification about this
        );
    }
    elsif ( !Whostmgr::Imunify360::is_imunify360_licensed() && !Whostmgr::Imunify360::is_imunify360_installed() ) {
        my $imunify360_price = Whostmgr::Imunify360::get_imunify360_price();
        my $store_url        = Cpanel::Config::Sources::get_source('STORE_SERVER_URL');
        my $url              = "$store_url/view/imunify360/license-options";

        my $purchase_link =
          $imunify360_price
          ? locale()->maketext( '[output,url,_1,Get Imunify360,_2,_3] for [_4].', $self->base_path('scripts12/purchase_imunify360_init'), 'target', '_parent', "\$$imunify360_price/month" )
          : locale()->maketext( '[output,url,_1,Get Imunify360,_2,_3].',          $self->base_path('scripts12/purchase_imunify360_init'), 'target', '_parent' );

        $self->add_warn_advice(
            key          => 'Imunify360_purchase',
            text         => locale()->maketext('Use [asis,Imunify360] to protect your server.'),
            suggestion   => locale()->maketext('[asis,Imunify360] blocks attacks in real-time using a combination of technologies, including Advanced Firewall, Intrusion Detection and Protection System, Malware Detection, [asis,Proactive Defense™], Patch Management, and Reputation Management.') . '<br /><br />' . $purchase_link,
            block_notify => 1,                                                                                                                                                                                                                                                                                                                 # Do not send a notification about this
        );
    }
    elsif ( !Whostmgr::Imunify360::is_imunify360_installed() ) {
        my $installation_link = locale()->maketext( '[output,url,_1,Install Imunify360,_2,_3].', $self->base_path('scripts12/install_imunify360'), 'target', '_parent' );

        $self->add_warn_advice(
            key          => 'Imunify360_install',
            text         => locale()->maketext('You have an [asis,Imunify360] license, but you do not have [asis,Imunify360] installed on your server.'),
            suggestion   => $installation_link,
            block_notify => 1,                                                                                                                                                                                                                                                                                                                 # Do not send a notification about this
        );
    }
    else {
        my $imunify_whm_link = locale()->maketext( '[output,url,_1,Open Imunify360,_2,_3].', $self->base_path('/cgi/imunify/handlers/index.cgi#/admin/dashboard/incidents'), 'target', '_parent' );

        $self->add_good_advice(
            key          => 'Imunify360_present',
            text         => locale()->maketext( q{Your server is protected by [asis,Imunify360]. For more information, read the [output,url,_1,documentation,_2,_3].}, 'https://www.imunify360.com/getting-started', 'target', '_blank' ),
            suggestion   => $imunify_whm_link,
            block_notify => 1,                                                                                                                                                                                                                                                                                                                 # Do not send a notification about this
        );
    }

    return 1;
}

sub _is_imunify360_supported {
    my $centos_version = Cpanel::Sys::OS::Check::get_strict_centos_version();
    my $os             = Cpanel::Sys::GetOS::getos();
    my $os_ok          = ( ( $os =~ /^centos$/ && ( $centos_version == 6 || $centos_version == 7 ) ) || $os =~ /^cloudlinux$/i );
    return $os_ok;
}

1;
