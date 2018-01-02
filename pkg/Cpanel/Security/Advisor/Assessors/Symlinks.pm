package Cpanel::Security::Advisor::Assessors::Symlinks;

# Copyright (c) 2016, cPanel, Inc.
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

use Cpanel::Sys::Uname ();

use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;

    if ( $self->has_cpanel_hardened_kernel() ) {
        $self->add_warn_advice(
            'key'  => 'Symlinks_protection_no_longer_support_hardened_kernel',
            'text' => $self->_lh->maketext('Unsupported cPanel hardened kernel detected.'),

            'suggestion' => $self->_lh->maketext(
                "[asis,cPanel] no longer supports the hardened kernel. We recommend that you use [asis,KernelCare's] free symlink protection. In order to enable [asis,KernelCare], you must replace the hardened kernel with a standard kernel. For instructions, please read the document on [output,url,_1,How to Manually Remove the cPanel-Provided Hardened Kernel,_2,_3].",
                'https://go.cpanel.net/uninstallhardenedkernel', 'target', '_blank'
            ),
        );

    }
    return 1;
}

sub has_cpanel_hardened_kernel {
    my $self         = shift;
    my $kernel_uname = ( Cpanel::Sys::Uname::get_uname_cached() )[2];
    my $ret;
    if ( $kernel_uname =~ m/(?:cpanel|cp)6\.x86_64/ ) {
        $ret = 1;
    }
    return $ret;
}

1;
