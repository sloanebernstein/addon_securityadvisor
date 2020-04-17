package Cpanel::Security::Advisor::Assessors::Kernel;

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
no warnings qw/once/;    # suppress perl warnings about the $Cpanel::KernelCare::KC_* package variables used in conditionals, in this subroutine only
use base 'Cpanel::Security::Advisor::Assessors';

use Cpanel::Version                                ();
use Cpanel::Security::Advisor::Assessors::Symlinks ();

# https://store.cpanel.net/json-api/products/cpstore
our $KC_PRICE_URL = q{https://store.cpanel.net};

sub version {
    return '1.06';
}

sub generate_advice {
    my ($self) = @_;

    if ( $self->_has_secure_boot ) {
        require Cpanel::KernelCare;
        my $kernelcare_state = Cpanel::KernelCare::get_kernelcare_state();
        if ( _has_kc_free_patch_set($kernelcare_state) || _has_kc_default_patch_set($kernelcare_state) ) {
            $self->_secure_boot_info( with_kernelcare => 1 );    # Show a warning that the system is currently in a bad state
        }
        else {
            $self->_secure_boot_info( with_kernelcare => 0 );    # Show an info notice that KernelCare is unavailable when Secure Boot is active
        }
    }
    else {
        # support for integrated KerneCare purchase/install is supported in 11.64 and above
        require Cpanel::Exception;
        require Cpanel::KernelCare;
        require Cpanel::KernelCare::Availability;
        require Cpanel::Kernel::Status;

        $self->_suggest_kernelcare;
        $self->_check_for_kernel_version;
    }

    return 1;
}

# free patch set is included in the extra patch set
sub _has_kc_free_patch_set {
    my $state = shift;
    return $state == $Cpanel::KernelCare::KC_FREE_PATCH_SET || $state == $Cpanel::KernelCare::KC_EXTRA_PATCH_SET;
}

# default patch set is included in the extra patch set
sub _has_kc_default_patch_set {
    my $state = shift;
    return $state == $Cpanel::KernelCare::KC_DEFAULT_PATCH_SET || $state == $Cpanel::KernelCare::KC_EXTRA_PATCH_SET;
}

sub _get_script_number() {
    my $current_version = Cpanel::Version::getversionnumber();
    my $is_v84_or_older = Cpanel::Version::compare( $current_version, '>=', '11.83' );

    return $is_v84_or_older ? 'scripts13' : 'scripts12';
}

sub _has_secure_boot {
    require Cpanel::FindBin;
    require Cpanel::SafeRun::Object;

    my $mokutil_bin = Cpanel::FindBin::findbin('mokutil');
    return 0 if !$mokutil_bin;

    my $obj = Cpanel::SafeRun::Object->new(
        program => $mokutil_bin,
        args    => ['--sb-state'],
    );
    return 0 if $obj->CHILD_ERROR;    # "EFI variables are not supported on this system"
    return ( ( $obj->stdout =~ /SecureBoot enabled/ || $obj->stderr =~ /SecureBoot enabled/ ) ? 1 : 0 );
}

sub _secure_boot_info {
    my ( $self, %detail ) = @_;

    if ( $detail{with_kernelcare} ) {
        $self->add_bad_advice(
            'key'          => 'Kernel_secureboot_and_kernelcare',
            'block_notify' => 1,
            'text'         => $self->_lh->maketext('[asis,KernelCare] is not compatible with Secure Boot.'),
            'suggestion'   => $self->_lh->maketext('This server uses Secure Boot but also has [asis,KernelCare]. [asis,KernelCare] is not compatible with Secure Boot and may not function correctly.'),
        );
    }
    else {
        $self->add_info_advice(
            'key'          => 'Kernel_secureboot_info',
            'block_notify' => 1,
            'text'         => $self->_lh->maketext('This server uses Secure Boot.'),
            'suggestion'   => $self->_lh->maketext('[asis,KernelCare] is not available when Secure Boot is active.'),
        );
    }

    return;
}

sub _suggest_kernelcare {
    my ($self) = @_;

    # Abort if the system won't benefit from KernelCare.
    return if !Cpanel::KernelCare::system_supports_kernelcare() || Cpanel::Security::Advisor::Assessors::Symlinks->new->has_cpanel_hardened_kernel();

    # Abort if kernelcare is already licensend
    return if eval { Cpanel::KernelCare::Availability::system_license_from_cpanel(); };

    my $kernelcare_state = Cpanel::KernelCare::get_kernelcare_state();

    my ( $promotion, $note );

    # Show alert for free state, even if we don't know "company_advertising_preferences"; show if KernelCare is
    # not installed or just the default (paid) patch is applied; do not show if free patch set or extra patch set
    # is detected
    my $is_ea4 = ( defined &Cpanel::Config::Httpd::is_ea4 && Cpanel::Config::Httpd::is_ea4() ) ? 1 : 0;

    if ( _has_kc_free_patch_set($kernelcare_state) ) {
        $promotion = $self->_lh->maketext(q{This free patch set protects your system from symlink attacks.});
        my $doclink = $self->_lh->maketext( q{For more information, read the [output,url,_1,documentation,_2,_3].}, ($is_ea4) ? 'https://go.cpanel.net/EA4Symlink' : 'https://go.cpanel.net/apachesymlink', 'target', '_blank' );
        $self->add_good_advice(
            'key'          => 'Kernel_kernelcare_free_symlink_protection_enabled',
            'block_notify' => 1,
            'text'         => q{You are Protected by KernelCare's Free Symlink Protection.},
            'suggestion'   => $promotion . ' ' . $doclink,
        );
    }

    # don't offer Free patch set if Default is detected - SWAT-780, or if on CloudLinux (KC free tier already baked into CL kernel)
    elsif ( $kernelcare_state != $Cpanel::KernelCare::KC_DEFAULT_PATCH_SET and Cpanel::KernelCare::system_supports_kernelcare_free() ) {
        my $doclink = $self->_lh->maketext( q{You can protect against this in multiple ways. Please review the following [output,url,_1,documentation,_2,_3] to find a solution that is suited to your needs.}, ($is_ea4) ? 'https://go.cpanel.net/EA4Symlink' : 'https://go.cpanel.net/apachesymlink', 'target', '_blank' );
        $promotion = $self->_lh->maketext(q{This free patch set protects your system from symlink attacks. Add KernelCare's Free Patch Set.});
        $note      = $self->_lh->maketext(q{NOTE: This is not the full KernelCare product and service.});
        my $link = $self->_lh->maketext(
            '[output,url,_1,Add KernelCare\'s Free Symlink Protection,_2,_3].',
            $self->base_path( _get_script_number() . '/add_kernelcare_free_symlink_protection' ),
            'target' => '_parent',
        );
        $self->add_bad_advice(
            'key'          => 'Kernel_kernelcare_suggest_free_symlink_protection',
            'block_notify' => 1,
            'text'         => q{Add KernelCare's Free Symlink Protection.},
            'suggestion'   => $promotion . ' ' . $link . ' ' . $note . '<br/><br/>' . $doclink,
        );
    }

    # Show KC symlink protection is active if free patch set or extra patch set is detected

    # if kernelcare is installed, and both default (paid) and free patch sets are applied, there is nothing to do so return to caller
    return if $kernelcare_state == $Cpanel::KernelCare::KC_EXTRA_PATCH_SET;

    my $advertising_preference = eval { Cpanel::KernelCare::Availability::get_company_advertising_preferences() };
    if ( my $err = $@ ) {
        if ( ref $err && $err->isa('Cpanel::Exception::HTTP::Network') ) {    # If we can't get the network, assume connections to cPanel are blocked.
            $advertising_preference = { disabled => 0, url => '', email => '' };
        }
        elsif ( ref $err && $err->isa('Cpanel::Exception::HTTP::Server') ) {    # If cPanel gives an error code, give customers the benefit of the doubt.
            return;                                                             # No advertising.
        }
        else {
            $self->add_warn_advice(
                key  => 'Kernel_kernelcare_preference_error',
                text => $self->_lh->maketext(
                    'The system cannot check the [asis,KernelCare] promotion preferences: [_1]',
                    Cpanel::Exception::get_string_no_id($err),
                ),
            );
            return;                                                             # No need to advertise; they will get a warning.
        }
    }

    # Abort if the customer requested we don't advertise - applies only to alert to pay for a license.
    return if $advertising_preference->{disabled};

    # Alert that this IP has a valid KernelCare license, but the RPM is not installed (offer link to install it)
    $promotion = $self->_lh->maketext('KernelCare provides an easy and effortless way to ensure that your operating system uses the most up-to-date kernel without the need to reboot your server.');
    if ( $kernelcare_state == $Cpanel::KernelCare::KC_MISSING ) {
        $self->add_bad_advice(
            'key'        => 'Kernel_kernelcare_valid_license_but_not_installed',
            'text'       => $self->_lh->maketext('Valid KernelCare License Found, but KernelCare is Not Installed.'),
            'suggestion' => $promotion . ' ' . $self->_lh->maketext(
                '[output,url,_1,Click to install,_2,_3].',
                $self->base_path( _get_script_number() . '/purchase_kernelcare_completion?order_status=success' ),
                'target' => '_parent',
            ),
        );
    }

    # Offer KernelCare upgrade to a paid license if KernelCare is either not installed or if KernelCare is installed and just the free patch set is applied
    #TODO - successful purchase flow handler needs to be updated to look for KC RPM/free patch set and merely apply default patch set if kernelcare is already installed
    elsif ( !_has_kc_default_patch_set($kernelcare_state) ) {
        my $suggestion;
        if ( $advertising_preference->{'url'} ) {
            $suggestion = $self->_lh->maketext(
                '[output,url,_1,Upgrade to KernelCare,_2,_3].',
                $advertising_preference->{'url'},
                'target' => '_parent',
            );
        }
        elsif ( $advertising_preference->{'email'} ) {
            $suggestion = $self->_lh->maketext(
                'For more information, [output,url,_1,email your provider,_2,_3].',
                'mailto:' . $advertising_preference->{'email'},
                'target' => '_blank',
            );
        }
        else {
            my $price = _get_kernelcare_monthly_price();
            $suggestion = $self->_lh->maketext(
                '[output,url,_1,Get KernelCare,_2,_3][_4].',
                $self->base_path( _get_script_number() . '/purchase_kernelcare_init' ),
                'target' => '_parent',
                ($price) ? qq{ for \$$price/month} : q{},
            );
        }

        $suggestion = ($suggestion) ? '<p/><p/>' . $suggestion : '';
        $promotion  = $self->_lh->maketext('KernelCare provides an easy and effortless way to ensure that your operating system uses the most up-to-date kernel without the need to reboot your server.');

        # Verifies the user is on CentOS 6 or 7, and is not running CloudLinux.
        if ( Cpanel::KernelCare::system_supports_kernelcare_free() ) {
            $promotion .= $self->_lh->maketext(' After you purchase and install KernelCare, you can obtain and install the KernelCare "Extra" Patchset, which includes symlink protection.');
        }

        $self->add_info_advice(
            'key'          => 'Kernel_kernelcare_purchase',
            'block_notify' => 1,
            'text'         => $self->_lh->maketext('Use KernelCare to automate kernel security updates without reboots.'),
            'suggestion'   => $promotion . ' ' . $suggestion,
        );
    }

    return 1;
}

sub _check_for_kernel_version {
    my ($self) = @_;

    my $kernel = eval { Cpanel::Kernel::Status::kernel_status( updates => 1 ) };

    if ( my $err = $@ ) {
        if ( ref $err && $err->isa('Cpanel::Exception::Unsupported') ) {
            $self->add_info_advice(
                'key'  => 'Kernel_unsupported_environment',
                'text' => $self->_lh->maketext( 'The system cannot update the kernel: [_1]', Cpanel::Exception::get_string_no_id($err) ),
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
        $self->_check_custom_kernel($kernel);
    }
    elsif ( !$kernel->{has_kernelcare} ) {
        $self->_check_standard_kernel($kernel);
    }
    else {
        $self->_check_kernelcare_kernel($kernel);
    }

    return 1;
}

sub _check_custom_kernel {
    my ( $self, $kernel ) = @_;

    if ( $kernel->{reboot_required} ) {
        $self->add_warn_advice(
            'key'  => 'Kernel_boot_running_mismatch',
            'text' => $self->_lh->maketext(
                'The system kernel is at version “[_1]”, but the system is configured to boot version “[_2]”.',
                $kernel->{running_version},
                $kernel->{boot_version},
            ),
            'suggestion' => $self->_lh->maketext(
                '[output,url,_1,Reboot the system,_2,_3]. If the problem persists, check the [asis,GRUB] boot configuration.',
                $self->base_path('scripts/dialog?dialog=reboot'),
                'target',
                '_blank'
            ),
        );
    }
    else {
        $self->add_info_advice(
            'key'  => 'Kernel_can_not_check',
            'text' => $self->_lh->maketext( 'Custom kernel version cannot be checked to see if it is up to date: [_1]', $kernel->{running_version} )
        );
    }
    return;
}

sub _check_standard_kernel {
    my ( $self, $kernel ) = @_;

    if ( $kernel->{update_available} && !$kernel->{update_excluded} ) {
        my $VRA = "$kernel->{update_available}{version}-$kernel->{update_available}{release}.$kernel->{update_available}{arch}";
        $self->add_bad_advice(
            'key'  => 'Kernel_outdated',
            'text' => $self->_lh->maketext(
                'The system kernel is at version “[_1]”, but an update is available: [_2]',
                $kernel->{running_version},
                $VRA,
            ),
            'suggestion' => _msg_update_and_reboot($self),
        );
    }
    elsif ( $kernel->{reboot_required} ) {
        $self->add_bad_advice(
            'key'  => 'Kernel_boot_running_mismatch',
            'text' => $self->_lh->maketext(
                'The system kernel is at version “[_1]”, but the system is configured to boot version “[_2]”.',
                $kernel->{running_version},
                $kernel->{boot_version},
            ),
            'suggestion' => $self->_lh->maketext(
                '[output,url,_1,Reboot the system,_2,_3]. If the problem persists, check the [asis,GRUB] boot configuration.',
                $self->base_path('scripts/dialog?dialog=reboot'),
                'target',
                '_blank'
            ),
        );
    }
    else {
        $self->add_good_advice(
            'key'  => 'Kernel_running_is_current',
            'text' => $self->_lh->maketext(
                'The system kernel is up-to-date at version “[_1]”.',
                $kernel->{running_version},
            ),
        );
    }
    return;
}

sub _check_kernelcare_kernel {
    my ( $self, $kernel ) = @_;

    if ( $kernel->{patch_available} ) {
        $self->add_bad_advice(
            'key'        => 'Kernel_kernelcare_update_available',
            'text'       => $self->_lh->maketext('A [asis,KernelCare] update is available.'),
            'suggestion' => _make_unordered_list(
                $self->_lh->maketext('You must take one of the following actions to ensure the system is up-to-date:'),
                $self->_lh->maketext(
                    'Patch the kernel (run “[_1]” on the command line).',
                    'kcarectl --update',
                ),
                _msg_update_and_reboot($self),    # TODO: Check update_available and reboot_required before recommending.
            ),
        );
    }
    elsif ( $kernel->{update_available} && !$kernel->{update_excluded} ) {
        if ( $kernel->{running_latest} ) {
            $self->add_info_advice(
                'key'  => 'Kernel_update_available',
                'text' => $self->_lh->maketext(
                    'The system kernel will now boot version “[_1]” instead of “[_2]”. Although [asis,KernelCare] still fully protects your server, we recommend that you reboot to the latest kernel version.',
                    $kernel->{running_version},
                    $kernel->{unpatched_version},
                ),
                'suggestion' => $self->_lh->maketext(
                    'Install the latest “[_1]” [asis,RPM] package to immediately boot into the latest kernel.',
                    'kernel',
                ),
            );
        }
        else {
            my $VRA = "$kernel->{update_available}{version}-$kernel->{update_available}{release}.$kernel->{update_available}{arch}";
            $self->add_info_advice(
                'key'  => 'Kernel_waiting_for_kernelcare_update',
                'text' => $self->_lh->maketext(
                    'The system kernel is at version “[_1]”, but an update is available: [_2]',
                    $kernel->{running_version},
                    $VRA,
                ),
                'suggestion' => _make_unordered_list(
                    $self->_lh->maketext('You must take one of the following actions to ensure the system is up-to-date:'),
                    $self->_lh->maketext('Wait a few days for [asis,KernelCare] to publish a kernel patch.'),
                    _msg_update_and_reboot($self),
                ),
            );
        }
    }
    elsif ( $kernel->{reboot_required} ) {
        $self->add_info_advice(
            'key'  => 'Kernel_waiting_for_kernelcare_update_2',
            'text' => $self->_lh->maketext(
                'The system kernel has changed from version “[_1]” to boot to version “[_2]”. While you are fully protected by KernelCare, it may still be a good idea to reboot into the latest system kernel at your earliest convenience.',
                $kernel->{unpatched_version},
                $kernel->{boot_version},
            ),
        );
    }
    else {
        $self->add_good_advice(
            'key'  => 'Kernel_kernelcare_is_current',
            'text' => $self->_lh->maketext(
                'KernelCare is installed and current running kernel version is up to date: [_1]',
                $kernel->{running_version},
            ),
        );
    }
    return;
}

sub _msg_update_and_reboot {
    my ($obj) = @_;
    return $obj->_lh->maketext(
        'Update the system (run “[_1]” on the command line), and [output,url,_2,reboot the system,_3,_4].',
        'yum -y update',
        $obj->base_path('scripts/dialog?dialog=reboot'),
        'target' => '_blank',
    );
}

# Do this to work around bad perltidy concatenation rules.
sub _make_unordered_list {
    my ( $title, @items ) = @_;

    my $output = $title;
    $output .= '<ul>';
    foreach my $item (@items) {
        $output .= "<li>$item</li>";
    }
    $output .= '</ul>';

    return $output;
}

sub _get_kernelcare_monthly_price {
    my $kernelcare_price_url = sprintf( "%s/json-api/products/cpstore", $KC_PRICE_URL );
    my $price;
    local $@;
    my $response = eval {
        my $http = Cpanel::HTTP::Client->new( verify_SSL => 1 )->die_on_http_error();
        $http->get($kernelcare_price_url);
    };

    # on error
    return $price if $@ or not $response;

    my $results = Cpanel::JSON::Load( $response->{'content'} );

    # unfortunately we have to iterate over all results to get the KernelCare results
  PRICE:
    foreach my $product ( @{ $results->{data} } ) {
        if ( $product->{short_name} eq q{Monthly KernelCare} ) {
            $price = $product->{price};
            last PRICE;
        }
    }
    return $price;
}

1;
