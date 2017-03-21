package Cpanel::Security::Advisor::Assessors::Kernel;

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
use base 'Cpanel::Security::Advisor::Assessors';
use Cpanel::JSON         ();
use Cpanel::OSSys::Env   ();
use Cpanel::Version      ();
use Cpanel::RPM          ();
use Cpanel::Logger       ();
use Cpanel::DIp::MainIP  ();
use Cpanel::NAT          ();
use Cpanel::HTTP::Client ();
use Cpanel::GenSysInfo   ();

our $VERIFY_SSL    = 1;
our $KC_CP_VERSION = q{11.63};
our $KC_VERIFY_URL = q{https://verify.cpanel.net};
our $KC_M2_URL     = q{manage2.cpanel.net};

sub version {
    return '1.04';
}

sub generate_advice {
    my ($self) = @_;

    # support for integrated KerneCare purchase/install is supported in 11.64 and above
    if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '>=', $KC_CP_VERSION ) ) {
        $self->_suggest_kernelcare;
    }

    if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.65' ) ) {
        require Cpanel::Kernel;
        require Cpanel::SafeRun::Errors;
        $self->_check_for_kernel_version_on_a_cpanel_whm_system_at_v64_or_earlier;
    }
    else {
        require Cpanel::Exception;
        require Cpanel::Kernel::Status;
        $self->_check_for_kernel_version;
    }

    return 1;
}

sub _suggest_kernelcare {
    my ($self) = @_;

    my $environment  = Cpanel::OSSys::Env::get_envtype();
    my $sysinfo      = Cpanel::GenSysInfo::run();
    my $manage2_data = _get_manage2_kernelcare_data();
    my $rpm          = Cpanel::RPM->new();

    if (    not $rpm->has_rpm(q{kernelcare})
        and not( $environment eq 'virtuozzo' || $environment eq 'lxc' )
        and $sysinfo->{'rpm_dist'} ne 'amazon'
        and not $manage2_data->{'disabled'} ) {

        my $promotion = $self->_lh->maketext('KernelCare provides an easy and effortless way to ensure that your operating system uses the most up-to-date kernel without the need to reboot your server.');

        # check to see this IP has a valid license even if it is not installed
        if ( _verify_kernelcare_license() ) {
            $self->add_bad_advice(
                'key'        => 'Kernel_kernelcare_valid_license_but_not_installed',
                'text'       => $self->_lh->maketext('Valid KernelCare License Found, but KernelCare is Not Installed.'),
                'suggestion' => $promotion . ' ' . $self->_lh->maketext(
                    '[output,url,_1,Click to install,_2,_3].',
                    $self->base_path('scripts12/purchase_kernelcare_completion?order_status=success'),
                    'target' => '_parent',
                ),
            );
        }
        else {
            my $suggestion = '';
            if ( $manage2_data->{'url'} ne '' ) {
                $suggestion = $self->_lh->maketext(
                    '[output,url,_1,Upgrade to KernelCare,_2,_3].',
                    $manage2_data->{'url'},
                    'target' => '_parent',
                );
            }
            elsif ( $manage2_data->{'email'} ne '' ) {
                $suggestion = $self->_lh->maketext(
                    'For more information, [output,url,_1,email your provider,_2,_3].',
                    'mailto:' . $manage2_data->{'email'},
                    'target' => '_blank',
                );
            }
            else {
                $suggestion = $self->_lh->maketext(
                    '[output,url,_1,Upgrade to KernelCare,_2,_3].',
                    $self->base_path('scripts12/purchase_kernelcare_init'),
                    'target' => '_parent',
                );
            }
            $self->add_warn_advice(
                'key'          => 'Kernel_kernelcare_purchase',
                'block_notify' => 1,
                'text'         => $self->_lh->maketext('Upgrade to KernelCare.'),
                'suggestion'   => $promotion . ' ' . $suggestion,
            );
        }
    }

    return 1;
}

sub _verify_kernelcare_license {
    my $mainserverip = Cpanel::NAT::get_public_ip( Cpanel::DIp::MainIP::getmainserverip() );
    my $verify_url = sprintf( "%s/ipaddrs.cgi?ip=%s", $KC_VERIFY_URL, $mainserverip );
    my $verified;
    local $@;
    my $response = eval {
        my $http = Cpanel::HTTP::Client->new( verify_SSL => $VERIFY_SSL )->die_on_http_error();
        $http->get($verify_url);
    };

    # on error
    return $verified if $@ or not $response;

    my $results = Cpanel::JSON::Load( $response->{'content'} );

    foreach my $current ( @{ $results->{'current'} } ) {
        if ( $current->{'package'} eq q{CPDIRECT-MONTHLY-KERNELCARE} and $current->{'product'} eq q{KernelCare} and $current->{'status'} eq 1 and $current->{'valid'} eq 1 ) {
            ++$verified;
            last;
        }
    }
    return $verified;
}

sub _get_manage2_kernelcare_data {
    my $companyfile = q{/var/cpanel/companyid};
    my $cid         = q{};
    if ( open my $fh, "<", $companyfile ) {
        $cid = <$fh>;
        chomp $cid;
        close $fh;
    }

    my $url = sprintf( 'https://%s/kernelcare.cgi?companyid=%d', $KC_M2_URL, $cid );
    local $@;
    my $raw_resp = eval {
        my $http = Cpanel::HTTP::Client->new( verify_SSL => $VERIFY_SSL, timeout => 10 )->die_on_http_error();
        $http->get($url);
    };

    # on error
    return { disabled => 0, url => '', email => '' } if $@ or not $raw_resp;

    my $json_resp;
    if ( $raw_resp->{'success'} ) {
        eval { $json_resp = Cpanel::JSON::Load( $raw_resp->{'content'} ) };

        if ($@) {
            $json_resp = { disabled => 0, url => '', email => '' };
        }
    }
    else {
        $json_resp = { disabled => 0, url => '', email => '' };
    }

    return $json_resp;
}

sub _check_for_kernel_version {
    my ($self) = @_;

    my $kernel = eval { Cpanel::Kernel::Status::kernel_status( updates => 1 ) };

    if ( my $err = $@ ) {
        if ( ref $err && $err->isa('Cpanel::Exception::Unsupported') ) {
            $self->add_info_advice(
                'key'  => 'Kernel_unsupported_environment',
                'text' => $self->_lh->maketext('Kernel updates are not supported on this virtualization platform. Be sure to keep the host’s kernel up to date.'),
            );
        }
        else {
            $self->add_warn_advice(
                'key'  => 'Kernel_check_error',
                'text' => $self->_lh->maketext( 'The system cannot check the kernel status: [_1]', Cpanel::Exception::get_string_no_id($err) ),
            );
        }
        return;    # Further checks are impossible without data.
    }

    if ( $kernel->{custom_kernel} ) {
        $self->add_info_advice(
            'key'  => 'Kernel_can_not_check',
            'text' => $self->_lh->maketext( 'Custom kernel version cannot be checked to see if it is up to date: [_1]', $kernel->{running_version} )
        );
    }
    elsif ( $kernel->{update_available} && !$kernel->{update_excluded} && $kernel->{has_kernelcare} ) {
        my $VRA = "$kernel->{update_available}{version}-$kernel->{update_available}{release}.$kernel->{update_available}{arch}";
        if ( $kernel->{patch_available} ) {
            $self->add_bad_advice(
                'key'  => 'Kernel_kernelcare_update_available',
                'text' => $self->_lh->maketext(
                    'Kernel patched with KernelCare, but out of date. running kernel: [_1], most recent kernel: [_2]',
                    $kernel->{running_version},
                    $VRA,
                ),
                'suggestion' => $self->_lh->maketext('This can be resolved either by running ’/usr/bin/kcarectl --update’ from the command line to begin an update of the KernelCare kernel version, or by running ’yum update’ from the command line and rebooting the system.'),
            );
        }
        else {
            $self->add_info_advice(
                'key'  => 'Kernel_waiting_for_kernelcare_update',
                'text' => $self->_lh->maketext(
                    'Kernel patched with KernelCare, but awaiting further updates. running kernel: [_1], most recent kernel: [_2]',
                    $kernel->{running_version},
                    $VRA,
                ),
                'suggestion' => $self->_lh->maketext('The kernel will likely be patched to the current version within the next few days. If this delay is unacceptable, update the system’s software by running ’yum update’ from the command line and reboot the system.'),
            );
        }
    }
    elsif ( $kernel->{update_available} && !$kernel->{update_excluded} ) {
        my $VRA = "$kernel->{update_available}{version}-$kernel->{update_available}{release}.$kernel->{update_available}{arch}";
        $self->add_bad_advice(
            'key'  => 'Kernel_outdated',
            'text' => $self->_lh->maketext(
                'Current kernel version is out of date. running kernel: [_1], most recent kernel: [_2]',
                $kernel->{running_version},
                $VRA,
            ),
            'suggestion' => $self->_lh->maketext('Update the system’s software by running ’yum update’ from the command line and reboot the system.'),
        );
    }
    elsif ( $kernel->{has_kernelcare} ) {
        $self->add_good_advice(
            'key'  => 'Kernel_kernelcare_is_current',
            'text' => $self->_lh->maketext( 'KernelCare is installed and current running kernel version is up to date: [_1]', $kernel->{running_version} )
        );
    }
    elsif ( $kernel->{reboot_required} ) {
        $self->add_bad_advice(
            'key'  => 'Kernel_boot_running_mismatch',
            'text' => $self->_lh->maketext(
                'Current kernel version does not match the kernel version for boot. running kernel: [_1], boot kernel: [_2]',
                $kernel->{running_version},
                $kernel->{boot_version},
            ),
            'suggestion' => $self->_lh->maketext(
                'Reboot the system in the "[output,url,_1,Graceful Server Reboot,_2,_3]" area. Check the boot configuration in grub.conf if the new kernel is not loaded after a reboot.',
                $self->base_path('scripts/dialog?dialog=reboot'),
                'target',
                '_blank'
            ),
        );
    }
    else {
        $self->add_good_advice(
            'key'  => 'Kernel_running_is_current',
            'text' => $self->_lh->maketext( 'Current running kernel version is up to date: [_1]', $kernel->{running_version} )
        );
    }

    return 1;
}

###################################################
#                                                 #
# Delete everything below here when v64 goes EOL. #
#                                                 #
###################################################

my $kc_kernelversion = kcare_kernel_version("uname");

sub _check_for_kernel_version_on_a_cpanel_whm_system_at_v64_or_earlier {
    my ($self) = @_;

    my %kernel_update = kernel_updates();
    my @kernel_update = ();
    if ( ( keys %kernel_update ) ) {
        foreach my $update ( keys %kernel_update ) {
            unshift( @kernel_update, $kernel_update{$update} );
        }
    }

    my $boot_kernelversion    = Cpanel::Kernel::get_default_boot_version();
    my $running_kernelversion = Cpanel::Kernel::get_running_version();
    my $environment           = Cpanel::OSSys::Env::get_envtype();

    if ( $running_kernelversion =~ m/\.(?:noarch|x86_64|i.86).+$/ ) {
        $self->add_info_advice(
            'key'  => 'Kernel_can_not_check',
            'text' => $self->_lh->maketext( 'Custom kernel version cannot be checked to see if it is up to date: [_1]', $running_kernelversion )
        );
    }
    elsif ( ( $environment eq 'virtuozzo' ) || ( $environment eq 'lxc' ) ) {
        $self->add_info_advice(
            'key'  => 'Kernel_unsupported_environment',
            'text' => $self->_lh->maketext('Kernel updates are not supported on this virtualization platform. Be sure to keep the host’s kernel up to date.')
        );
    }
    elsif ( (@kernel_update) && ($kc_kernelversion) ) {
        if ( kcare_kernel_version("check") eq "New version available" ) {
            $self->add_bad_advice(
                'key'  => 'Kernel_kernelcare_update_available',
                'text' => $self->_lh->maketext(
                    'Kernel patched with KernelCare, but out of date. running kernel: [_1], most recent kernel: [list_and,_2]',
                    $kc_kernelversion,
                    \@kernel_update,
                ),
                'suggestion' => $self->_lh->maketext('This can be resolved either by running ’/usr/bin/kcarectl --update’ from the command line to begin an update of the KernelCare kernel version, or by running ’yum update’ from the command line and rebooting the system.'),
            );
        }
        else {
            $self->add_info_advice(
                'key'  => 'Kernel_waiting_for_kernelcare_update',
                'text' => $self->_lh->maketext(
                    'Kernel patched with KernelCare, but awaiting further updates. running kernel: [_1], most recent kernel: [list_and,_2]',
                    $kc_kernelversion,
                    \@kernel_update,
                ),
                'suggestion' => $self->_lh->maketext('The kernel will likely be patched to the current version within the next few days. If this delay is unacceptable, update the system’s software by running ’yum update’ from the command line and reboot the system.'),
            );
        }
    }
    elsif ( (@kernel_update) ) {
        $self->add_bad_advice(
            'key'  => 'Kernel_outdated',
            'text' => $self->_lh->maketext(
                'Current kernel version is out of date. running kernel: [_1], most recent kernel: [list_and,_2]',
                $running_kernelversion,
                \@kernel_update,
            ),
            'suggestion' => $self->_lh->maketext('Update the system’s software by running ’yum update’ from the command line and reboot the system.'),
        );
    }
    elsif ($kc_kernelversion) {
        $self->add_good_advice(
            'key'  => 'Kernel_kernelcare_is_current',
            'text' => $self->_lh->maketext( 'KernelCare is installed and current running kernel version is up to date: [_1]', $kc_kernelversion )
        );
    }
    elsif ( ( $running_kernelversion ne $boot_kernelversion ) ) {
        $self->add_bad_advice(
            'key'  => 'Kernel_boot_running_mismatch',
            'text' => $self->_lh->maketext(
                'Current kernel version does not match the kernel version for boot. running kernel: [_1], boot kernel: [_2]',
                $running_kernelversion,
                $boot_kernelversion
            ),
            'suggestion' => $self->_lh->maketext(
                'Reboot the system in the "[output,url,_1,Graceful Server Reboot,_2,_3]" area. Check the boot configuration in grub.conf if the new kernel is not loaded after a reboot.',
                $self->base_path('scripts/dialog?dialog=reboot'),
                'target',
                '_blank'
            ),
        );
    }
    else {
        $self->add_good_advice(
            'key'  => 'Kernel_running_is_current',
            'text' => $self->_lh->maketext( 'Current running kernel version is up to date: [_1]', $running_kernelversion )
        );
    }

    return 1;
}

sub kernel_updates {
    my %kernel_update;
    my @args         = qw(yum -d 0 info updates kernel);
    my @yum_response = Cpanel::SafeRun::Errors::saferunnoerror(@args);
    my ( $rpm, $arch, $version, $release );

    foreach my $element ( 0 .. $#yum_response ) {
        $rpm     = ( split( /:/, $yum_response[$element] ) )[1] if ( ( $yum_response[$element] =~ m/^Name/ ) );
        $arch    = ( split( /:/, $yum_response[$element] ) )[1] if ( ( $yum_response[$element] =~ m/^Arch/ ) );
        $version = ( split( /:/, $yum_response[$element] ) )[1] if ( ( $yum_response[$element] =~ m/^Version/ ) );
        $release = ( split( /:/, $yum_response[$element] ) )[1] if ( ( $yum_response[$element] =~ m/^Release/ ) );
        if ( ( ($rpm) && ($arch) && ($version) && ($release) ) ) {
            s/\s//g foreach ( $rpm, $arch, $version, $release );
            if ( $kc_kernelversion ne ( $version . "-" . $release . "." . $arch ) && $kc_kernelversion ne ( $version . "-" . $release ) ) {
                $kernel_update{ $rpm . " " . $version . "-" . $release } = $version . "-" . $release . "." . $arch;
                $rpm                                                     = undef;
                $arch                                                    = undef;
                $version                                                 = undef;
                $release                                                 = undef;
            }
        }
    }

    return %kernel_update;
}    # end of sub

sub kcare_kernel_version {
    my @args;
    my $kc_response = "";

    if ( -f "/usr/bin/kcarectl" ) {
        @args = ( "/usr/bin/kcarectl", "--" . "$_[0]" );
        $kc_response = Cpanel::SafeRun::Errors::saferunnoerror(@args);
        $kc_response =~ s/\+$//;
        chomp $kc_response;
    }

    return $kc_response;
}

########################################
#                                      #
# Delete above here when v64 goes EOL. #
#                                      #
########################################

1;
