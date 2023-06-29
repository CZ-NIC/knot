#!/usr/bin/env perl

# This package is needed on Debian derived ditributions: libnet-dbus-perl

use Net::DBus;
use Net::DBus::Reactor;
use Time::HiRes;

my $bus = Net::DBus->system;

# Get a handle to the 'knotd' service
my $knotd;
while (true) {
    eval {
        $knotd = $bus->get_service("cz.nic.knotd");
    };
    if (!$@) {
        last;
    }
    sleep(0.1);
}

# Get the device manager
my $knotd_interface = $knotd->get_object("/cz/nic/knotd", "cz.nic.knotd.events");

$knotd_interface->connect_to_signal('started', sub
{
    print "Server started\n";
});

$knotd_interface->connect_to_signal('stopped', sub
{
    print "Server stopped\n";
});

$knotd_interface->connect_to_signal('zone_updated', sub
{
    my ($zone, $serial) = @_;
    print "Updated zone=$zone to serial=$serial\n";
});

$knotd_interface->connect_to_signal('keys_updated', sub
{
    my ($zone) = @_;
    print "Keys updated for zone=$zone\n";
});

$knotd_interface->connect_to_signal('zone_ksk_submission', sub
{
    my ($zone, $key_tag, $kasp_id) = @_;
    print "Ready KSK for zone=$zone keytag=$key_tag keyid=$kasp_id\n";
});

$knotd_interface->connect_to_signal('zone_dnssec_invalid', sub
{
    my ($zone) = @_;
    print "Invalid DNSSEC for zone=$zone\n";
});

# Main loop
Net::DBus::Reactor->main->run();

exit 0
