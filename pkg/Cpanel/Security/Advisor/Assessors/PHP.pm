package Cpanel::Security::Advisor::Assessors::PHP;

# Copyright 2019, cPanel, L.L.C.
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
use base 'Cpanel::Security::Advisor::Assessors';
use Cpanel::Result ();

my $php_ver_regex = '^ea-php(\d{2,3})$';

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_php_eol();
    return 1;
}

sub _check_for_php_eol {
    my $self = shift;
    require Cpanel::API::EA4;

    my $result = Cpanel::Result->new();
    Cpanel::API::EA4::get_recommendations( undef, $result );
    my $reco_data    = $result->{'data'} if $result;
    my @php_ver_keys = grep { $_ =~ /$php_ver_regex/ } ( keys %$reco_data );

    my @eol_php_versions = ();
    my $eol_reco_data;
    foreach my $key (@php_ver_keys) {
        my @recos = @{ $reco_data->{$key} };
        foreach (@recos) {
            if ( grep { $_ eq 'eol' } @{ $_->{'filter'} } ) {

                # Recommendation data is same for all EOL PHP versions. Storing only one such instance
                # here to use later in the advice.
                $eol_reco_data = $_ if ( !$eol_reco_data );
                push @eol_php_versions, _get_readable_php_version_format($key);
            }
        }
    }

    # Return if there is no EOL PHPs.
    return if scalar @eol_php_versions == 0;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    $security_advisor_obj->add_advice(
        {
            'key'        => 'Php_versions_going_eol',
            'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
            'text'       => $self->_lh->maketext( '[list_and,_1] reached [output,acronym,EOL,End of Life][comment,title]', \@eol_php_versions ),
            'suggestion' => _make_unordered_list( map { $_->{'text'} } @{ $eol_reco_data->{'options'} } )
              . $self->_lh->maketext( 'Go to [output,url,_1,MultiPHP Manager page] and update to a supported version.',  $self->base_path('scripts2/multiphp_manager') ) . ' '
              . $self->_lh->maketext( 'For more information, read [output,url,_1,PHP EOL Documentation,target,_blank].', 'https://www.php.net/supported-versions.php' ),
        }
    );

    return 1;
}

sub _get_readable_php_version_format {
    my ($php_version) = @_;
    my $readable_php_version;
    if ( $php_version =~ /$php_ver_regex/ ) {
        my $second_part = $1;
        $second_part =~ s/(\d)$/\.$1/;
        $readable_php_version = "PHP $second_part";
    }
    return $readable_php_version;
}

sub _make_unordered_list {
    my (@items) = @_;

    my $output = '<ul>';
    foreach my $item (@items) {
        $output .= "<li>$item</li>";
    }
    $output .= '</ul>';

    return $output;
}

1;
