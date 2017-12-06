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

use Lchown ();

use Cpanel::TempFile      ();
use Cpanel::GenSysInfo    ();
use Cpanel::Config::Httpd ();

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
    my $self                  = shift;
    my $hardened_kernel_state = $self->_check_for_symlink_kernel_patch();
    my $ret;
    if ( $hardened_kernel_state eq q{Symlinks_protection_enabled_for_centos6} ) {
        $ret = 1;
    }
    return $ret;
}

# returns truthy if any of the associated sysctls are set
sub _enforcing_symlink_ownership {
    my $self = shift;

    my @sysctls = qw(
      /proc/sys/kernel/grsecurity/enforce_symlinksifowner
      /proc/sys/fs/enforce_symlinksifowner
    );

    foreach my $sysctl (@sysctls) {
        if ( -e $sysctl ) {
            return 1;
        }
    }

    return 0;
}

# returns truthy if any of the associated sysctls are set
sub _symlink_enforcement_gid {
    my $self = shift;

    my @sysctls = qw(
      /proc/sys/kernel/grsecurity/symlinkown_gid
      /proc/sys/fs/symlinkown_gid
    );

    foreach my $sysctl (@sysctls) {
        if ( -e $sysctl ) {
            open my $fh, q{<}, $sysctl or die $!;
            my $val = <$fh>;
            close $fh;
            chomp $val;
            return int $val;
        }
    }

    return undef;
}

# checks to see if grsec patch is applied to the running kernel, first by
# looking at associated sysctls; then by attempting a benign symlink escallation attack
sub _check_for_symlink_kernel_patch {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    my $sysinfo = Cpanel::GenSysInfo::run();

    #
    # This test only pertains to RHEL/CentOS 6.
    #
    return 1 unless $sysinfo->{'rpm_dist_ver'} == 6;

    my $is_ea4 = ( defined &Cpanel::Config::Httpd::is_ea4 && Cpanel::Config::Httpd::is_ea4() ) ? 1 : 0;

    #
    # If a grsecurity kernel is not detected, then we should recommend that
    # the administrator install one.
    #
    unless ( $self->_enforcing_symlink_ownership() ) {

        # You do not appear to have any symlink protection enabled through a properly patched kernel on this server, which provides additional protections beyond those solutions employed in userland. Please review [output,url,_1,the documentation,_2,_3] to learn how to apply this protection.
        return q{Symlinks_no_kernel_support_for_ownership_attacks_1};
    }

    my $gid = $self->_symlink_enforcement_gid();

    unless ( defined $gid ) {

        # You do not appear to have any symlink protection enabled through a properly patched kernel on this server, which provides additional protections beyond those solutions employed in userland. Please review [output,url,_1,the documentation,_2,_3] to learn how to apply this protection.
        return q{Symlinks_no_kernel_support_for_ownership_attacks_2};
    }

    # Attempt at a benign symlink attack, if it fails we assume symlink protection is not in place
    my $shadow = '/etc/shadow';
    my $tmpobj = Cpanel::TempFile->new;
    my $dir    = $tmpobj->dir;
    my $link   = "$dir/shadow";

    chmod 0755, $dir;

    symlink $shadow => $link or die "Unable to symlink() $shadow to $link: $!";

    Lchown::lchown( $gid, $gid, $link ) or die "Unable to lchown() $link: $!";

    {
        local $) = $gid;

        if ( open my $fh, '<', $link ) {

            # You do not appear to have any symlink protection enabled through a properly patched kernel on this server, which provides additional protect beyond those solutions employed in userland. Please review the following documentation to learn how to apply this protection.
            return q{Symlinks_protection_not_enabled_for_centos6};
        }
        else {
            # Kernel symlink protection is enabled for CentOS 6.
            return q{Symlinks_protection_enabled_for_centos6};
        }
    }

    return undef;
}

1;
