package Cpanel::Security::Advisor::Assessors::_Self;

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
use base 'Cpanel::Security::Advisor::Assessors';

use Cpanel::RPM::Versions::File ();
use Cpanel::Version             ();

# The purpose of this assessor module is to report conditions which may render
# the provided advice untrustworthy or invalid. Currently, this is limited to
# determining whether the RPM database is acting as expected, since several
# other assessors rely on good RPM data.

# Logic behind this number: A barebones CentOS 6 container has 129(?) RPM packages.
# Round down to one significant figure.
use constant OS_RPM_COUNT_WARN_THRESHOLD => 100;

sub version { return '1.01'; }

sub generate_advice {
    my ($self) = @_;

    # XXX assume distro is RPM-based if cPanel version is past version 98
    # Below can be simplified once support for these older versions ends.
    my $is_rpm_based   = 1;
    my $cpanel_version = Cpanel::Version::getversionnumber();
    if ( Cpanel::Version::compare( $cpanel_version, '>=', '11.99' ) ) {
        require Cpanel::OS;
        $is_rpm_based &&= Cpanel::OS::is_rpm_based();
    }

    $self->_check_rpm() if $is_rpm_based;

    return 1;
}

sub _check_rpm {
    my ($self) = @_;

    # Both primes the cache and ensures that the test is run.
    my $installed_rpms = $self->get_installed_rpms();

    my $cache = $self->{'security_advisor_obj'}->{'_cache'};
    if ( exists $cache->{'timed_out'} && $cache->{'timed_out'} ) {
        $self->add_bad_advice(
            'key'          => 'RPM_timed_out',
            'text'         => $self->_lh->maketext('Security Advisor timed out while reading the RPM database of packages.'),
            'suggestion'   => $self->_lh->maketext( "Security Advisor may include inaccurate results until it can fully read the RPM database. To resolve this, reduce the load on your system and then rebuild the RPM database with the following interface: [output,url,_1,Rebuild RPM Database,_2,_3].", $self->base_path('scripts/dialog?dialog=rebuildrpmdb'), 'target', '_blank' ),
            'block_notify' => 1,
        );
    }
    elsif ( exists $cache->{'died'} && $cache->{'died'} ) {
        $self->add_bad_advice(
            'key'          => 'RPM_broken',
            'text'         => $self->_lh->maketext('Security Advisor detected RPM database corruption.'),
            'suggestion'   => $self->_lh->maketext( "Security Advisor may include inaccurate results until it can cleanly read the RPM database. To resolve this, rebuild the RPM database with the following interface: [output,url,_1,Rebuild RPM Database,_2,_3].", $self->base_path('scripts/dialog?dialog=rebuildrpmdb'), 'target', '_blank' ),
            'block_notify' => 1,
        );
    }
    elsif ( ref $installed_rpms eq 'HASH' && scalar keys %$installed_rpms <= scalar( keys %{ Cpanel::RPM::Versions::File->new()->list_rpms_in_state('installed') } ) + OS_RPM_COUNT_WARN_THRESHOLD ) {
        $self->add_warn_advice(
            'key'          => 'RPM_too_few',
            'text'         => $self->_lh->maketext('The RPM database is smaller than expected.'),
            'suggestion'   => $self->_lh->maketext("Security Advisor may include inaccurate results if the RPM database of packages is incomplete. To resolve this, check the cPanel update logs for RPM issues."),
            'block_notify' => 1,
        );
    }

    return;
}

1;
