package Cpanel::Security::Advisor::Assessors::Processes;

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

use Cpanel::Sys::OS::Check ();
use Cpanel::Version        ();

sub version {
    return '1.01';
}

sub generate_advice {
    my ($self) = @_;

    if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.65' ) ) {
        require Cpanel::FileUtils::Path;
        require Cpanel::SafeRun::Object;
        require Cpanel::Sys::OS;
        $self->_check_for_outdated_processes_on_a_cpanel_whm_system_at_v64_or_earlier;
    }
    else {
        require Cpanel::Exception;
        require Cpanel::ProcessCheck::Outdated;
        $self->_check_for_outdated_processes;
    }

    return 1;
}

sub _check_for_outdated_processes {
    my ($self) = @_;

    my $reboot = eval { Cpanel::ProcessCheck::Outdated::reboot_suggested() };
    if ( my $err = $@ ) {
        if ( ref $err && $err->isa('Cpanel::Exception::Service::BinaryNotFound') ) {
            $self->add_info_advice(
                key        => 'Processes_unable_to_check_running_executables',
                text       => $self->_lh->maketext('Unable to check whether running executables are up-to-date.'),
                suggestion => $self->_lh->maketext(
                    'Install the ‘[_1]’ command to check if processes are up-to-date.',
                    $err->get('service'),
                ),
            );
            return;    # Cannot check any other cases, so abort.
        }
        elsif ( !ref $err || !$err->isa('Cpanel::Exception::Unsupported') ) {
            $self->add_warn_advice(
                key  => 'Processes_error_while_checking_reboot',
                text => $self->_lh->maketext( 'Failed to determine if a reboot is necessary: [_1]', Cpanel::Exception::get_string_no_id($err) ),
            );
        }
    }

    if ($reboot) {
        $self->add_bad_advice(
            key        => 'Processes_detected_running_from_outdated_executables',
            text       => $self->_lh->maketext('The system’s core libraries or services have been updated.'),
            suggestion => $self->_lh->maketext(
                '[output,url,_1,Reboot the server,_2,_3] to ensure the system benefits from these updates.',
                $self->base_path('scripts/dialog?dialog=reboot'),
                'target',
                '_blank',
            ),
        );
        return;    # No need to check further.
    }

    my @services = eval { Cpanel::ProcessCheck::Outdated::outdated_services() };
    if ( my $err = $@ ) {
        if ( !ref $err || !$err->isa('Cpanel::Exception::Unsupported') ) {
            $self->add_warn_advice(
                key  => 'Processes_error_while_checking_running_services',
                text => $self->_lh->maketext( 'Failed to check whether active services are up-to-date: [_1]', Cpanel::Exception::get_string_no_id($err) ),
            );
        }
    }

    if (@services) {
        my $restart_cmd = 'systemctl restart';
        if ( !Cpanel::Sys::OS::Check::has_systemd() ) {
            $restart_cmd = 'service';
            @services = map { s/\.service$//r } @services;
        }
        $self->add_bad_advice(
            key  => 'Processes_detected_running_outdated_services',
            text => $self->_lh->maketext(
                'Detected [quant,_1,service,services] that [numerate,_1,is,are] running outdated executables: [join, ,_2]',
                scalar @services,
                \@services,
            ),
            suggestion => _make_unordered_list(
                $self->_lh->maketext('You must take one of the following actions to ensure the system is up-to-date:'),
                $self->_lh->maketext(
                    'Restart the listed [numerate,_1,service,services] using “[_2]”; then click “[_3]” to check non-service processes.',
                    scalar @services,
                    $restart_cmd,
                    'Scan Again',    # Not translated in pkg/templates/main.tmpl
                ),
                $self->_lh->maketext(
                    '[output,url,_1,Reboot the server,_2,_3].',
                    $self->base_path('scripts/dialog?dialog=reboot'),
                    'target',
                    '_blank',
                ),
            ),
        );
        return;                      # No need to check further.
    }

    my @PIDs = eval { Cpanel::ProcessCheck::Outdated::outdated_processes() };
    if ( my $err = $@ ) {
        if ( !ref $err || !$err->isa('Cpanel::Exception::Unsupported') ) {
            $self->add_warn_advice(
                key  => 'Processes_error_while_checking_running_executables',
                text => $self->_lh->maketext( 'Failed to check whether running executables are up-to-date: [_1]', Cpanel::Exception::get_string_no_id($err) ),
            );
        }
        return;                      # We can't check anything, so don't report anything.
    }

    if (@PIDs) {
        my $suggestion;
        if ( grep { $_ eq '1' } @PIDs ) {    # If initd or systemd needs update, just suggest reboot.
            $suggestion = $self->_lh->maketext(
                '[output,url,_1,Reboot the server,_2,_3] to ensure the system benefits from these updates.',
                $self->base_path('scripts/dialog?dialog=reboot'),
                'target',
                '_blank',
            );
        }
        else {
            $suggestion = _make_unordered_list(
                $self->_lh->maketext('You must take one of the following actions to ensure the system is up-to-date:'),
                $self->_lh->maketext(
                    'Restart the listed [numerate,_1,process,processes].',
                    scalar @PIDs,
                ),
                $self->_lh->maketext(
                    '[output,url,_1,Reboot the server,_2,_3].',
                    $self->base_path('scripts/dialog?dialog=reboot'),
                    'target',
                    '_blank',
                )
            );
        }

        $self->add_bad_advice(
            key  => 'Processes_detected_running_outdated_executables',
            text => $self->_lh->maketext(
                'Detected [quant,_1,process,processes] that [numerate,_1,is,are] running outdated executables: [join, ,_2]',
                scalar @PIDs,
                \@PIDs,
            ),
            suggestion => $suggestion,
        );
        return;    # Error reported.
    }

    $self->add_good_advice(
        key  => 'Processes_none_with_outdated_executables',
        text => $self->_lh->maketext('The system did not detect processes with outdated binaries.')
    );

    return 1;
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

sub _check_for_outdated_processes_on_a_cpanel_whm_system_at_v64_or_earlier {
    my ($self) = @_;

    # Prior to CentOS 6, the yum-utils package did not come with /usr/bin/needs-restarting
    return if Cpanel::Sys::OS::getreleaseversion() < 6;

    # needs-restarting won't work without smaps support (Disabled in grsec kernels).
    return if !-e qq{/proc/$$/smaps};

    # Find the needs-restarting executable, if available.
    my $package_install_cmd = 'yum install yum-utils';
    my $command             = 'needs-restarting';
    my $exec                = Cpanel::FileUtils::Path::findinpath($command);

    if ( !$exec ) {
        $self->add_info_advice(
            'key'      => 'Processes_unable_to_check_running_executables',
            text       => $self->_lh->maketext('Unable to check whether running executables are up-to-date.'),
            suggestion => $self->_lh->maketext( 'Install the ‘[_1]’ command by running ‘[_2]’ on the command line to get notifications when executables are updated but the existing processes are not restarted.', $command, $package_install_cmd ),
        );
    }
    else {
        my $proc = Cpanel::SafeRun::Object->new( program => $exec );

        if ( $proc->stdout() ) {
            $self->add_bad_advice(
                'key'      => 'Processes_detected_running_from_outdated_executables',
                text       => $self->_lh->maketext('Detected processes that are running outdated binary executables.'),
                suggestion => $self->_lh->maketext(
                    'Reboot the system in the “[output,url,_1,Graceful Server Reboot,_2,_3]” area.  Alternatively, [asis,SSH] into this server and run ‘[_4]’, then manually restart each of the listed processes.',
                    $self->base_path('scripts/dialog?dialog=reboot'),
                    'target',
                    '_blank',
                    $exec,
                ),
            );
        }
        elsif ( $proc->CHILD_ERROR() ) {
            $self->add_warn_advice(
                'key' => 'Processes_error_while_checking_running_executables_1',
                text  => $self->_lh->maketext( 'An error occurred while attempting to check whether running executables are up-to-date: [_1]', $proc->autopsy() ),
            );
        }
        elsif ( $proc->stderr() ) {
            $self->add_warn_advice(
                'key' => 'Processes_error_while_checking_running_executables_2',
                text  => $self->_lh->maketext( 'An error occurred while attempting to check whether running executables are up-to-date: [_1]', $proc->stderr() ),
            );
        }
        else {
            $self->add_good_advice(
                key  => 'Processes_none_with_outdated_executables',
                text => $self->_lh->maketext('No processes with outdated binaries detected.')
            );
        }
    }

    return 1;
}

1;
