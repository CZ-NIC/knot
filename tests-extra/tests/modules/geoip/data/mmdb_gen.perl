#!/usr/bin/perl
use MaxMind::DB::Writer::Tree;

my %types = (
    country       => 'map',
    iso_code      => 'utf8_string',
    city          => 'map',
    geoname_id    => 'uint32',
);

my @iso_codes = ('AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AQ', 'AR', 'AS', 'AT',
                 'AU', 'AW', 'AX', 'AZ', 'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI',
                 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ', 'BQ', 'BR', 'BS', 'BT', 'BV', 'BW',
                 'BY', 'BZ', 'CA', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM',
                 'CN', 'CO', 'CR', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK',
                 'DM', 'DO', 'DZ', 'EC', 'EE', 'EG', 'EH', 'ER', 'ES', 'ET', 'FI', 'FJ',
                 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI',
                 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK',
                 'HM', 'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ',
                 'IR', 'IS', 'IT', 'JE', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM',
                 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI', 'LK', 'LR',
                 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF', 'MG', 'MH',
                 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV',
                 'MW', 'MX', 'MY', 'MZ', 'NA', 'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO',
                 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL',
                 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU',
                 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL',
                 'SM', 'SN', 'SO', 'SR', 'SS', 'ST', 'SV', 'SX', 'SY', 'SZ', 'TC', 'TD',
                 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO', 'TR', 'TT', 'TV',
                 'TW', 'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG',
                 'VI', 'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW');

my $tree = MaxMind::DB::Writer::Tree->new(
    ip_version               => 6,
    record_size              => 24,
    database_type            => 'GeoIP Test Data',
    languages                => ['en'],
    description              => { en => 'Knot DNS GeoIP module test data' },
    map_key_type_callback    => sub { $types{ $_[0] } },
    remove_reserved_networks => 0
);

$network_counter = 0;

foreach $iso_code (@iso_codes) {
    $network_counter++;
    $tree->insert_network(
        '127.255.'.$network_counter.'.0/24',
        {
            country => {
                iso_code => $iso_code
            },
            city => {
              geoname_id => $network_counter
            }
        }
    );
};
        
open my $fh, '>:raw', 'db.mmdb';
$tree->write_tree($fh);
