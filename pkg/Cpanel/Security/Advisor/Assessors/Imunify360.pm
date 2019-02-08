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
use Cpanel::cPStore         ();
use Cpanel::DIp::MainIP     ();
use Cpanel::Exception       ();
use Cpanel::HTTP::Client    ();
use Cpanel::JSON            ();
use Cpanel::NAT             ();
use Cpanel::Server::Type    ();
use Cpanel::Version         ();
use Cpanel::RPM             ();

use Cpanel::Imports;

our $IMUNIFY360_PRODUCT_ID            = 'IMUNIFY360';          # TODO: Update this string as needed
our $IMUNIFY360_PACKAGE_ID_RE         = qr/\bIMUNIFY360\b/;    # TODO: Verify that this is correct
our $IMUNIFY360_MINIMUM_CPWHM_VERSION = '11.79';               # we want it usable on both development and release builds for 11.80

# These two short names were verified as correct 2019-02-08 using https://aa.store.manage.testing.cpanel.net/
our $IMUNIFY360_STORE_SHORTNAME_UNL  = 'monthly_imunify360_unlimited';
our $IMUNIFY360_STORE_SHORTNAME_SOLO = 'monthly_imunify360_solo';

sub version {
    return '1.00';
}

sub generate_advice {
    my ($self) = @_;

    eval {
        if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '>=', $IMUNIFY360_MINIMUM_CPWHM_VERSION ) ) {

            $self->_suggest_imunify360;
        }
    };
    if ( my $exception = $@ ) {
        print STDERR $exception;    # STDERR gets sent to ULC/logs/error_log.
        die $exception;
    }

    return 1;
}

sub _suggest_imunify360 {
    my ($self) = @_;

    if ( !$self->_is_imunify360_licensed ) {
        my $imunify360_price = _get_imunify360_price();
        my $store_url        = Cpanel::Config::Sources::get_source('STORE_SERVER_URL');
        my $url              = "$store_url/view/imunify360/license-options";
        my $purchase_link    = locale()->maketext( '[output,url,_1,Get Imunify360,_2,_3] for [_4].', $url, 'target', '_blank', "\$$imunify360_price/month" );
        $self->add_warn_advice(
            key          => 'Imunify360_purchase',
            text         => locale()->maketext('Use [asis,Imunify360] to protect your server against attacks.'),
            suggestion   => locale()->maketext('[asis,Imunify360] blocks attacks in real-time using a combination of technologies, including [asis,Proactive Defense™], which stops new attacks that scanners are not yet able to identify.') . '<br /><br />' . $purchase_link,
            block_notify => 1,                                                                                                                                                                                                                                                       # Do not send a notification about this
        );
    }
    elsif ( !$self->_is_imunify360_installed ) {

        $self->add_warn_advice(
            key          => 'Imunify360_install',
            text         => locale()->maketext('You have an [asis,Imunify360] license, but you do not have [asis,Imunify360] installed on your server.'),
            suggestion   => locale()->maketext('Install [asis,Imunify360].'),
            block_notify => 1,                                                                                                                                                                                                                                                       # Do not send a notification about this
        );
    }
    else {
        $self->add_good_advice(
            key          => 'Imunify360_present',
            text         => locale()->maketext('Your server is protected by [asis,Imunify360].'),
            block_notify => 1,                                                                                                                                                                                                                                                       # Do not send a notification about this
        );
    }

    return 1;
}

sub _is_imunify360_licensed {
    my ($self) = @_;

    my $mainip = Cpanel::NAT::get_public_ip( Cpanel::DIp::MainIP::getmainserverip() );

    my $http = Cpanel::HTTP::Client->new( timeout => 20 )->die_on_http_error();
    my $response = $http->get( Cpanel::Config::Sources::get_source('VERIFY_URL') . q{/ipaddrs.cgi?ip=} . $mainip );
    die Cpanel::Exception::create('HTTP') if !$response->{success};

    my $data = Cpanel::JSON::Load( $response->{content} );

    foreach my $license ( @{ $data->{current} } ) {
        return 1
          if $license->{product} eq $IMUNIFY360_PRODUCT_ID
          && $license->{package} =~ $IMUNIFY360_PACKAGE_ID_RE
          && $license->{status} eq 1    # Means 'active'
          && $license->{valid} eq 1;
    }

    # For QA purposes:
    #  This touch file doesn't grant any actual ability to use Imunify360 as if it were licensed; it just tricks
    #  the Security Advisor into skipping the promotional message and going right to the "installed" check.
    return 1 if -f '/var/cpanel/imunify360_skip_promo';

    return 0;
}

sub _is_imunify360_installed {
    my ($self) = @_;
    my $rpm = Cpanel::RPM->new();

    return $rpm->has_rpm(q{imunify360-firewall});
}

sub _get_imunify360_product {
    my $store        = Cpanel::cPStore->new();
    my $product_list = $store->get('products/cpstore');

    my $is_cpanel_solo = ( Cpanel::Server::Type::get_max_users() == 1 );

    my $product_shortname =
        $is_cpanel_solo
      ? $IMUNIFY360_STORE_SHORTNAME_SOLO
      : $IMUNIFY360_STORE_SHORTNAME_UNL;

    foreach my $product (@$product_list) {
        return $product if $product->{'short_name'} eq $product_shortname;
    }

    return;
}

sub _get_imunify360_price {
    my $product = _get_imunify360_product;
    if ( ref $product eq 'HASH' && $product->{price} ) {
        return $product->{price};
    }
    return;
}

1;
