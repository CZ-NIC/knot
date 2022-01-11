#!/usr/bin/env perl

use Net::DBus;
use Net::DBus::Reactor;

my $bus = Net::DBus->system;

# Get a handle to the 'knotd' service
my $knotd = $bus->get_service("cz.nic.knotd");

# Get the device manager
my $knotd_interface = $knotd->get_object("/cz/nic/knotd", "cz.nic.knotd.events");

$knotd_interface->connect_to_signal('zone_updated', sub
{
    my ($zone, $serial) = @_;
    print "Zone $zone updated, SOA serial $serial\n";
});

# Main loop
Net::DBus::Reactor->main->run();

exit 0
