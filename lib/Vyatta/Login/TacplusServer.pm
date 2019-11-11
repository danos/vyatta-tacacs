# **** License ****
#
# Copyright (c) 2018-2019, AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2014-2016 Brocade Communications Systems, Inc.
# All rights reserved.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2007-2013 Vyatta, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# **** End License ****

package Vyatta::Login::TacplusServer;

use strict;
use warnings;

use File::Compare;
use File::Copy "cp";
use File::Slurp;
use Net::IP;
use POSIX qw(:signal_h);
use Readonly;

use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Vyatta::DSCP qw(dscp_lookup);

my $package = 'tacplus';	# pam package name

Readonly my $TACACS_CFG => "/etc/tacplus/server";
Readonly my $TACACS_TMP => "/tmp/tacplus_server.$$";
Readonly my $TACACS_PATH_DEFAULT => 'system login tacplus-server';
Readonly my $TACACS_PATH_VRF => 'routing routing-instance';
Readonly my $TACACS_GLOBAL_PATH => 'system tacplus-options server';
Readonly my $TACACS_ACCOUNTING_PATH => 'system tacplus-options command-accounting';
Readonly my $TACACS_ACCOUNTING_BROADCAST_PATH => 'system tacplus-options accounting broadcast';

Readonly my $SSSD_TACPLUS_SCRIPT => "/opt/vyatta/sbin/vyatta_update_tacplus_server";
Readonly my $PAM_AUTH_UPDATE_TACACS => "/opt/vyatta/sbin/vyatta_tacacs_pam_auth_update";
Readonly my $PAM_AUTH_UPDATE_TACACS_CONF => "/usr/share/pam-configs/vyatta-sssd-tacacs";

Readonly my $TACACS_ENV => "/var/run/tacplus.env";
Readonly my $TACPLUSD => 'tacplusd';

my $TACACS_PATH;
my $TACACS_VRF;
my @VRFS = ();
my $TACACS_PID = "/var/run/tacplusd";

sub remove_pam_tacplus {
    system("DEBIAN_FRONTEND=noninteractive " .
	   " pam-auth-update --package --remove vyatta-sssd-tacacs") == 0
	or die "pam-auth-update remove vyatta-sssd-tacacs failed";

    unlink($PAM_AUTH_UPDATE_TACACS_CONF);
    return;
}

# Check if the tacplus server is configured on the
# system. This function will look at default and
# non-default VRFs
sub check_tacplus_status {

    my $path;
    my $exists = 0;
    my $rconfig = Vyatta::Config->new();
    if ($rconfig->exists($TACACS_PATH_DEFAULT) || 
       $rconfig->existsOrig($TACACS_PATH_DEFAULT)) {
       push @VRFS, "default";
    }
    if ($rconfig->exists($TACACS_PATH_VRF)) {
       my @vrf = $rconfig->listNodes($TACACS_PATH_VRF);
       for my $vrf ( @vrf ) {
           if ($rconfig->exists("$TACACS_PATH_VRF $vrf $TACACS_PATH_DEFAULT")) {
               push @VRFS, $vrf;
           }
       }
    }
    if ($rconfig->existsOrig($TACACS_PATH_VRF)) {
       my @vrf = $rconfig->listOrigNodes($TACACS_PATH_VRF);
       for my $vrf ( @vrf ) {
           if ($rconfig->existsOrig("$TACACS_PATH_VRF $vrf $TACACS_PATH_DEFAULT")) {
               push @VRFS, $vrf;
           }
       }
    }
    #check if tacplus is configured elsewhere in this session
    for my $rdid (@VRFS) {
        if ( $rdid eq "default" ) {
            $path = "$TACACS_PATH_DEFAULT";
        } else {
            $path = "$TACACS_PATH_VRF $rdid $TACACS_PATH_DEFAULT";
        }
        my $rconfig = Vyatta::Config->new($path);
        my $tcount = scalar($rconfig->listNodes());
       $exists = 1 if ($tcount > 0);
    }
    return $exists;
}

my %x = (
        " " => "\\s",
        "\t" => "\\t",
        "\r" => "\\r",
        "\n" => "\\n",
        "\\" => "\\\\",
);

sub escape
{
    my $str = shift;

    $str =~ s/[ \t\r\n\\]/$x{$&}/eg;
    $str;
}

sub dscp_val_to_dec {
    my $val = shift;
    return dscp_lookup($val) // $val;
}

sub setup_tacplusd {

    my ($gstatus, $vrf_exists) = @_;
    my $rc;
    my $count   = 0;
    my $rconfig = Vyatta::Config->new();

    open (my $cfg, '>', $TACACS_TMP)
        or die "Can't open config tmp: '$TACACS_CFG\-$TACACS_VRF' ($!)";

    chmod(0600, $cfg);

    print $cfg "# TACACS+ configuration file\n",
               "# automatically generated do not edit\n",
               "# Server\tSecret\tTimeout\n";

    print $cfg "\n[general]\n";

    printf $cfg "BroadcastAccounting=%s\n", ($rconfig->exists($TACACS_ACCOUNTING_BROADCAST_PATH) ? "true" : "false");

    # eventually needs to be exposed
    printf $cfg "SetupTimeout=%d\n", 2;

    printf $cfg "Dscp=%s\n", dscp_val_to_dec(
        $rconfig->returnValue("$TACACS_GLOBAL_PATH dscp") // "cs6");

    $rconfig->setLevel($TACACS_PATH);
    my @servers = $rconfig->listNodes();
    my %serverStatus = $rconfig->listNodeStatus();

    # maintain ordering from configd
    for my $server ( @servers ) {
        my $status = $serverStatus{$server};

        next if ( $status eq 'deleted' );

        my $port    = $rconfig->returnValue("$server port");

        my $secret  = $rconfig->returnValue("$server secret");
        die "Missing secret for $server\n"
            unless $secret;

        my $timeout = $rconfig->returnValue("$server timeout");
        die "Missing timeout for $server\n"
            unless $timeout;

        my $addr = $server;

        my $hold_down = $rconfig->returnValue("$server hold-down-timer");
        my $source = $rconfig->returnValue("$server source-address");
        my $source_intf = $rconfig->returnValue("$server source-interface");

        ++$count;

        printf $cfg "[server%d]\nAddress=%s\nPort=%s\nSecret=%s\nTimeout=%s\n".
                    "HoldDown=%s\n",
            $count, $addr, $port, escape($secret), $timeout, $hold_down;

        printf $cfg "SourceAddress=%s\n", $source if (defined $source);
        printf $cfg "SourceInterface=%s\n", $source_intf if (defined $source_intf);
    }

    close($cfg);

    if ( compare( "$TACACS_CFG\-$TACACS_VRF", $TACACS_TMP ) != 0 ) {
        cp ($TACACS_TMP, "$TACACS_CFG\-$TACACS_VRF")
            or die "Install of $TACACS_TMP to $TACACS_CFG failed";
    }

    if (scalar @servers > 0) {
        write_name_env();
        #write the file name to env file
        open (my $env, '>>', $TACACS_ENV)
            or die "Can't open env file: $TACACS_ENV ($!)";
        chmod(0600, $env);
        print $env "CONFIG=$TACACS_CFG\-$TACACS_VRF\n";
        close($env);
    }

    if ($TACACS_VRF ne "default") {
        if (!-d "/run/systemd/system") {
            die "Cannot start tacacs daemon: Requires systemd";
        }

        #Just before starting tacplusd in a routing-instance,
        #stop the tacplusd in default RD if it's running there
        system("service", $TACPLUSD, "stop");
        if ( $gstatus eq "added" && $#VRFS != 0 ) {
            for my $instance (@VRFS) {
                if ($instance ne "default") {
                    system("service", "$TACPLUSD\@$instance", "stop");
                }
            }
        }
    }

    my $TACACS_DAEMON = $TACPLUSD;
    $TACACS_DAEMON .= "@".$TACACS_VRF unless ($TACACS_VRF eq "default");

    if ($gstatus eq "added") {
        system("service", $TACACS_DAEMON, "start");
    }
    elsif ($gstatus eq "deleted") {
        system("service", $TACACS_DAEMON, "stop");
    }
    elsif ($gstatus eq "changed") {
        if (-e "$TACACS_PID-$TACACS_VRF.pid") {
            system("service", $TACACS_DAEMON, "reload")
        }
        else {
            system("service", $TACACS_DAEMON, "start");
        }
    }
    unlink($TACACS_TMP);
}

sub setup_sssd_tacplus {
    my ($status, $chain_prio, $enforce, $vrf_exists) = @_;

    my $temp_status = $status;
    $temp_status = "added"
        if ($temp_status eq "deleted" && $vrf_exists);
    if ($temp_status ne "deleted") {
        my $rc = system("$SSSD_TACPLUS_SCRIPT $temp_status 2>&1");
        die "Updating SSSD for TACACS+ configuration failed:\n$rc" if ($?);
    }

    remove_pam_tacplus();
    my $rconfig = Vyatta::Config->new($TACACS_PATH);
    my $count = scalar($rconfig->listNodes());
    # load pam again if there is tacplus servers configured in same session
    if ( ($status ne "disable") && ($vrf_exists || $count > 0) ) {
         my $PAM_AUTH_UPDATE_PARAM = "$chain_prio";
         $PAM_AUTH_UPDATE_PARAM = "$PAM_AUTH_UPDATE_PARAM enforce" if defined($enforce);
         my $rc = system("$PAM_AUTH_UPDATE_TACACS $PAM_AUTH_UPDATE_PARAM 2>&1");
         die "Updating PAM auth configuration or TACACS+ failed:\n$rc" if ($?);
    }
    return;
}

sub setup_tacacs_path {
    my $status = shift; 
    my $rconfig = Vyatta::Config->new();
    $TACACS_VRF = "default";
    my @action = ("added", "changed", "static", "disable");

    if ( $status eq "deleted" || $status eq "disable" ) {
        if ($rconfig->existsOrig($TACACS_PATH_DEFAULT)) {
            $TACACS_PATH = $TACACS_PATH_DEFAULT;
        } elsif ($rconfig->existsOrig($TACACS_PATH_VRF)) {
            my @vrf = $rconfig->listOrigNodes($TACACS_PATH_VRF);
            for my $vrf ( @vrf ) {
                if ($rconfig->existsOrig("$TACACS_PATH_VRF $vrf $TACACS_PATH_DEFAULT")) {
                    $TACACS_PATH = "$TACACS_PATH_VRF $vrf $TACACS_PATH_DEFAULT";
                    $TACACS_VRF = $vrf;
                }
            }
        }
    } 
    if ( grep ( /^$status$/, @action ) ) {
        if ($rconfig->exists($TACACS_PATH_DEFAULT)) {
            $TACACS_PATH = $TACACS_PATH_DEFAULT;
        } elsif ($rconfig->exists($TACACS_PATH_VRF)) {
            my @vrf = $rconfig->listNodes($TACACS_PATH_VRF);
            for my $vrf ( @vrf ) {
                if ($rconfig->exists("$TACACS_PATH_VRF $vrf $TACACS_PATH_DEFAULT")) {
                    $TACACS_PATH = "$TACACS_PATH_VRF $vrf $TACACS_PATH_DEFAULT";
                    $TACACS_VRF = $vrf;
                    return;
                }
            }
        }    
    }
}

sub write_name_env {
    $TACACS_VRF = ( defined($TACACS_VRF) ? $TACACS_VRF : 'default' );
    #write vrf to the env file for tacacs 
    open (my $env, '>', $TACACS_ENV)
        or die "Can't open env file: $TACACS_ENV ($!)";
    chmod(0600, $env);
    print $env "VRF=$TACACS_VRF\n";
    close($env);
}

sub update {
    my ($this, $status, $chain_prio, $enforce) = @_;
    setup_tacacs_path($status);
    my $vrf_exists = check_tacplus_status();
    setup_sssd_tacplus($status, $chain_prio, $enforce, $vrf_exists);

    setup_tacplusd($status, $vrf_exists);
    return;
}

1;
