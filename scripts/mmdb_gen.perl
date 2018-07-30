#!/usr/bin/perl
use MaxMind::DB::Writer::Tree;

my %types = (
    continent     => 'map',
    code          => 'utf8_string',
    country       => 'map',
    iso_code      => 'utf8_string',
    city          => 'map',
    names         => 'map',
    en            => 'utf8_string',
    geoname_id    => 'uint32',
);


my $tree = MaxMind::DB::Writer::Tree->new(
    ip_version            => 6,
    record_size           => 24,
    database_type         => 'GeoIP Test Data',
    languages             => ['en'],
    description           => { en => 'Knot DNS GeoIP module test data' },
    map_key_type_callback => sub { $types{ $_[0] } },
);

$tree->insert_network(
    '203.0.113.0/24',
    {
        continent => {
            geoname_id => 1,
            code       => 'AS',
            names      => {
                en => 'Asia',
            },
        },
        country => {
            geoname_id => 2,
            iso_code   => 'CN',
            names      => {
                en => 'China',
            },
        },
        city => {
            geoname_id => 3,
            names      => {
                en => 'Fuzhou',
            },
        },
    },
);


open my $fh, '>:raw', '../tests-extra/tests/modules/geoip/data/db.mmdb';
$tree->write_tree($fh);
