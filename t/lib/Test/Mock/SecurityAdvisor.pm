package Test::Mock::SecurityAdvisor;

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

use Test::MockModule qw/strict/;
use Test::MockFile;

use Cpanel::Comet::Mock       ();
use Cpanel::JSON              ();
use Cpanel::Security::Advisor ();

use constant {
    COMET_CHANNEL => 'securityadvisor',
};

sub new {
    return bless {
        '_comet' => Cpanel::Comet::Mock->new(),
      },
      __PACKAGE__;
}

sub new_advisor_object {
    my ($self) = @_;
    return Cpanel::Security::Advisor->new( 'comet' => $self->{'_comet'}, 'channel' => COMET_CHANNEL() );
}

sub mock_all {
    my ($self) = @_;

    $self->set_assessor_module('Cpanel::Security::Advisor::Assessors::MockAssessor');

    $self->mock_func(
        'Cpanel::Logger',
        'warn' => sub {

            # For testing CPANEL-33980. Clobber $@ a.k.a. $EVAL_ERROR because that's what Cpanel::Logger does.
            eval { die 'Not what you expected, grasshopper?' };
            return 1;
        }
    );

    $self->mock_func(
        'Cpanel::LoadModule',
        'load_perl_module' => sub {
            my $module = shift;
            if ( index( $module, 'Cpanel::Security::Advisor::Assessors' ) >= 0 && index( $module, 'Mock' ) == -1 ) {
                die "Attempting to load an unmocked assessor module: $module";
            }

            # Otherwise, make a real attempt to load the module.
            return $self->get_mock_module('Cpanel::LoadModule')->original('load_perl_module')->($module);
        }
    );

    return;
}

sub set_assessor_module {
    my ( $self, $module ) = @_;
    $self->mock_func(
        'Cpanel::LoadModule::AllNames',
        'get_loadable_modules_in_namespace' => sub {
            return { $module => 'testing' };
        }
    );
    return;
}

sub get_advisor_messages {
    my ($self) = @_;
    my @decoded;
    for my $msg ( @{ $self->{'_comet'}->get_messages( COMET_CHANNEL() ) } ) {
        push @decoded, Cpanel::JSON::Load($msg);
    }
    return \@decoded;
}

sub get_mock_module {
    my ( $self, $module ) = @_;
    die "No mock for $module exists" unless exists $self->{'_module'}->{$module};
    return $self->{'_module'}->{$module};
}

sub get_func_calls {
    my ( $self, $module, $func ) = @_;
    die "No mock for ${module}::${func} exists" unless exists $self->{'_module'}->{$module} && $self->{'_module'}->{$module}->is_mocked($func);
    return $self->{'_calls'}->{$module}->{$func};
}

sub mock_func {
    my ( $self, $module, $func, $impl ) = @_;
    if ( !exists $self->{'_module'}->{$module} ) {
        $self->{'_module'}->{$module} = Test::MockModule->new($module);
    }
    @{ $self->{'_calls'}->{$module}->{$func} } = ();
    $self->{'_module'}->{$module}->redefine(
        $func => sub {
            push @{ $self->{'_calls'}->{$module}->{$func} }, [@_];
            if ( ref $impl eq 'CODE' ) {
                return $impl->(@_);
            }
            return $impl;
        }
    );
    return $self->{'_module'}->{$module};
}

sub mock_file {
    my ( $self, $dir, $file, $contents ) = @_;
    my $fullpath = $dir . q{/} . $file;

    if ( exists $self->{'_file'}->{$dir} ) {
        $self->{'_file'}->{$dir}->contents( [ sort( @{ $self->{'_file'}->{$dir}->contents() }, $file ) ] );
    }
    else {
        $self->{'_file'}->{$dir} = Test::MockFile->dir( $dir, [$file] );
    }

    $self->{'_file'}->{$fullpath} = Test::MockFile->file( $fullpath, $contents );

    return;
}

1;
