package Test::Assessor;

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
# DISCLAIMED. IN NO EVENT SHALL cPanel, L.L.C. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;

use Cpanel::Locale ();
use Cpanel::Security::Advisor ();    # For ADVISE_GOOD, et. al.

sub new {
    my ( $class, %options ) = @_;

    my $module_name = "Cpanel::Security::Advisor::Assessors::$options{assessor}";

    my $self = bless {
        locale => Cpanel::Locale->get_handle(),
        advice => [],
    }, $class;

    eval "require $module_name" or die $@;    ##no critic (ProhibitStringyEval) -- require $module_name; doesn't work for some reason.
    my $assessor = "$module_name"->new($self);
    $self->{assessor} = $assessor;

    return $self;
}

sub generate_advice {
    my ($self) = @_;
    return $self->{assessor}->generate_advice();
}

sub add_advice {
    my ( $self, $advice ) = @_;

    # Some assessor modules call methods directly on instances of this class,
    # and some use wrapper methods, so try to figure out the module name
    # regardless of which path we took.
    my ( $module, $function );
    foreach my $level ( 1, 3 ) {
        my $caller = ( caller($level) )[3];
        if ( $caller =~ /(Cpanel::Security::Advisor::Assessors::.+)::([^:]+)$/ ) {
            ( $module, $function ) = ( $1, $2 );
            last;
        }
    }

    push @{ $self->{advice} }, {
        module   => $module,
        function => $function,
        advice   => $advice,
    };

    return;
}

sub get_advice {
    my ($self) = @_;
    return $self->{advice};
}

sub clear_advice {
    my ($self) = @_;
    $self->{advice} = [];
    return;
}

1;
