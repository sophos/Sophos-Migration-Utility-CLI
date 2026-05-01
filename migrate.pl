#!/usr/bin/perl
#Copyright Sophos Ltd 2026
#
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

package SMU::Migrate;

use strict;
use warnings;
use v5.10.1;

use Getopt::Std;
use Storable;
use HTML::Template;
use Archive::Tar;
use JSON;
use Encode;
use Socket qw(inet_aton inet_ntoa);

our $VERSION = '1.1';
# Sophos Migration Utility - CLI
# Compatible with UTM 9.7xx to SFOS APIVersion 2105.1
#
## Known issues and limitations
#
# 1. Tag and FilterAction List Website -> URL Group export
#     - Regexes are not exported (SFOS restriction)
#     - CIDR URLs are not exported (SFOS restriction)
#     - URLs containing paths are not exported (SFOS restriction)
#     - UTM's "include subdomains" is ignored. URL Groups always include subdomains on SFOS
#     - SFOS only allows 128 URLs per group. This tool will split them and create multple URL Groups when necessary.
# 2. SFOS generally allows shorter names for objects than UTM. Names are truncated where necessary.
# 3. DNS Groups -> IPLists is disabled - See DNSGrouptoIPLIST in sub parse_one_host_from_dns_group() to re-enable
# 4. Gateway hosts -> Gateways export is best-effort; interface and family fidelity can vary by route source object type.

# 5. SFOS validates the VPN connections more strictly than UTM. Because of this, some configurations that are valid in UTM may be rejected by SFOS import validation.
# It is not feasible to reimplement all the SFOS validation rules, so this tool will only detect a limited number of issues that may cause problems, as mentioned below.  Please be advised there may be more situations that will cause SFOS to reject the settings.
#     - Pre-shared key length must be at least 5 characters
#     - VPN connections must have well defined networks - can't use "Any" as network definitions

# 6. This version will import the local ID (usually a hostname) from UTM into SFOS.
# 7. Users and groups are not imported.  For VPN definitions, they have to be added manually.
# 8. Nested service and network groups are not imported, as they are not supported in SFOS.
#
## Supported exports
#   - URL Groups (Filter Actions allow/block lists, tags, local sites)
#   - Services (TCP/UDP/TCPUDP, IP/ESP/AH, ICMP/ICMPv6) and Service Groups
#   - Hosts (IP/FQDN/MAC), Networks/Ranges, Network Groups, FQDN Host Groups, Country Groups
#   - DNS Host entries (static DNS)
#   - Gateway Hosts -> Gateways (IPv4/IPv6 where resolvable)
#   - Static routes (unicast)
#   - Policy routes (route/policy -> SDWANPolicyRoute)
#   - Schedules (recurring and one-time)
#   - Certificates
#   - VPN (IPsec profiles + site-to-site connections; SSL tunnel settings; SSL VPN server/client; SSL VPN remote access policy)
#   - Application Filter policy
#   - PPTP remote access configuration
#   - Firewall Rules
#   - NAT Rules
#   - ATP settings/exceptions
#   - Time settings
#   - NTP servers
#   - DoS settings + bypass rules
#   - DHCP servers (IPv4/IPv6)
#   - Web Filter exceptions
#   - PIM-SM (main.pim_sm -> PIMDynamicRouting, static RP mode)
#
## Unsupported exports to be considered
#   - Routes (beyond static routes and policy routes)
#   - VLANs
#   - Firewall Rules - Groups

my $DEBUG = 0;
my $CONFD = "/usr/local/bin/confd-client.plx";
my $SNAPSHOT_DIR = "/var/confd/var/storage/snapshots/";
my $HTML_TEMPLATE_DIR = './tmpl/';
my $DEFAULT_INTERFACE_NAME = 'Port1';
my $DEFAULT_DHCP_INTERFACE_NAME = 'Port1';
my $LOG_FIREWALL = 0;
my $MIGRATE_FIREWALL_RULES = 1;
our $NAT_STRATEGY = 'compat';
our $CONTRACT_BASELINE = '2105.1';
our $MIGRATION_REPORT_FILE = '';

our %MIGRATION_REPORT = (
    baseline => $CONTRACT_BASELINE,
    warnings => [],
    stats => {},
);

my $INTERFACE_ROUTE_NAME = 'Port1';

our %UNSUPPORTED_CLASS_TYPE_WARNED = ();

use lib '.';
use Protocols qw/$IP_PROTOS $ICMP4 $ICMP6/;
use Digest::MD5 qw(md5_hex);

our %TEMPLATE_METADATA = (
    'Header.tmpl' => { },
    'Footer.tmpl' => { },
    'GatewayHost.tmpl' => { handler => \&parse_one_gatewayhost, class_types => ['itfparams/primary', 'route/policy'] },
    'SDWANPolicyRoute.tmpl' => { handler => \&parse_sdwan_policy_routes, class_types => [] },
    'Host.tmpl' => { handler => \&parse_one_host, class_types => ['network/dns_host', 'network/host', 'network/network', 'network/interface_network', 'network/range', 'network/dns_group', 'network/availability_group', 'network/interface_address', 'network/interface_broadcast', 'mac_list/mac_list'] },
    'DNSHostEntry.tmpl' => { handler => \&parse_dns_host_entries, class_types => [] },
    'URLGroup.tmpl' => { handler => \&parse_one_url_group, class_types => ['http/cff_action'] },
    'Services.tmpl' => { handler => \&parse_one_service, class_types => ['service/tcp', 'service/udp', 'service/tcpudp', 'service/icmp', 'service/icmpv6', 'service/ip', 'service/esp', 'service/ah', 'service/any'] },
    'UnicastRoute.tmpl' => { handler => \&parse_one_static_route, class_types => ['route/static'] },
    'PIMDynamicRouting.tmpl' => { handler => \&parse_pim_dynamic_routing, class_types => [] },
    'Schedule.tmpl' => { handler => \&parse_one_schedule, class_types => ['time/recurring', 'time/single'] },
    # this is used for both s2s and remote access!
    'SSLTunnelAccessSettings.tmpl' => { handler => \&parse_ssl_tunnel_access_settings, class_types => [] },
    'Certificate.tmpl' => { handler => \&parse_one_certificate, class_types => ['ca/host_key_cert'], extra_data_path => 'Files/CertificateFile/' },
    'VPNProfile.tmpl' => { handler => \&parse_one_ipsec_vpn_profile, class_types => ['ipsec/policy'] },
    'VPNIPSecConnection.tmpl' => { handler => \&parse_one_ipsec_vpn_connection, class_types => ['ipsec_connection/site_to_site'] },
    'SiteToSiteServer.tmpl' => { handler => \&parse_one_ssl_vpn_server, class_types => ['ssl_vpn/server_connection'] },
    'SiteToSiteClient.tmpl' => { handler => \&parse_one_ssl_vpn_client, class_types => ['ssl_vpn/client_connection'], extra_data_path => 'Files/ServerConfigurationFile/' },
    'ApplicationFilterPolicy.tmpl' => { handler => \&parse_application_filter_policy, class_types => ['application_control/rule'] },
    'PPTPConfiguration.tmpl' => { handler => \&parse_remote_access_pptp_configuration },
    'SSLVPNPolicy.tmpl' => { handler => \&parse_remote_access_ssl_vpn, class_types => [ 'ssl_vpn/remote_access_profile' ] },
    'IPHostGroup.tmpl' => { handler => \&parse_one_host_group, class_types => ['network/group'] },
    'FQDNHostGroup.tmpl' => { handler => \&parse_fqdn_host_groups, class_types => [] },
    'CountryGroup.tmpl' => { handler => \&parse_geoip_country_groups, class_types => [] },
    'ServiceGroup.tmpl' => { handler => \&parse_service_group, class_types => ['service/group'] },
    'FirewallRule.tmpl' => { handler => \&parse_firewall_rule, class_types => ['packetfilter/packetfilter', 'packetfilter/mangle'] },
    'ATP.tmpl' => { handler => \&parse_atp, class_types => [] },
    'Time.tmpl' => { handler => \&parse_time_settings, class_types => [] },
    'NTPServer.tmpl' => { handler => \&parse_ntp_server, class_types => [] },
    'DoSSettings.tmpl' => { handler => \&parse_dos_settings, class_types => [] },
    'DoSBypassRules.tmpl' => { handler => \&parse_dos_bypass_rule, class_types => ['ips/exception'] },
    'NAT.tmpl' => { handler => \&parse_nat_rule, class_types => ['packetfilter/nat', 'packetfilter/1to1nat', 'packetfilter/loadbalance', 'packetfilter/masq'] },
    'DHCPServer.tmpl' => { handler => \&parse_dhcp_servers, class_types => [] },
    'DHCPServerIpv6.tmpl' => { handler => \&parse_dhcp_servers_ipv6, class_types => ['dhcp/server6'] },
    'WebFilterException.tmpl' => { handler => \&parse_web_filter_exception, class_types => ['http/exception'] },
);

our %CLASS_TYPE_TO_TEMPLATE;
while (my ($template_name, $data) = each %TEMPLATE_METADATA) {
    my $class_type_list = $data->{class_types};
    next if ref($class_type_list) ne 'ARRAY';
    for my $ct (@$class_type_list) {
        $CLASS_TYPE_TO_TEMPLATE{$ct} = $template_name;
    }
}

my %CLASS_TYPE_HANDLERS = (
    'http/lsl_tag' => sub { my ($backup, $obj) = @_; return $obj; },
    'http/local_site' => sub { my ($backup, $obj) = @_; return $obj; },
);

my %POST_HANDLERS = (
    'URLGroup.tmpl' => { handler => \&parse_url_groups_from_tags_and_sites, class_types => ['http/lsl_tag', 'http/local_site'] },
);

our @ORDER = (
    'Header.tmpl',
    'Host.tmpl',
    'DNSHostEntry.tmpl',
    'GatewayHost.tmpl',
    'Services.tmpl',
    'UnicastRoute.tmpl',
    'PIMDynamicRouting.tmpl',
    'URLGroup.tmpl',
    'IPHostGroup.tmpl',
    'FQDNHostGroup.tmpl',
    'CountryGroup.tmpl',
    'ServiceGroup.tmpl',
    'SDWANPolicyRoute.tmpl',
    'Schedule.tmpl',
    'Certificate.tmpl',
    'VPNProfile.tmpl',
    'VPNIPSecConnection.tmpl',
    'SSLTunnelAccessSettings.tmpl',
    'SiteToSiteServer.tmpl',
    'SiteToSiteClient.tmpl',
    'ApplicationFilterPolicy.tmpl',
    'PPTPConfiguration.tmpl',
    'SSLVPNPolicy.tmpl',
    'ATP.tmpl',
    'Time.tmpl',
    'DoSSettings.tmpl',
    'DoSBypassRules.tmpl',
    'DHCPServer.tmpl',
    'DHCPServerIpv6.tmpl',
    'WebFilterException.tmpl',
    'FirewallRule.tmpl',
    'NAT.tmpl',
    'NTPServer.tmpl',
    'Footer.tmpl',
);

our $SFOS_GEOIP_COUNTRY_HOSTMAP_DATA = <<'EOF';
AD|Andorra
AE|United Arab Emirates
AF|Afghanistan
AG|Antigua and Barbuda
AI|Anguilla
AL|Albania
AM|Armenia
AN|Netherlands Antilles
AO|Angola
AP|Asia/Pacific Region
AQ|Antarctica
AR|Argentina
AS|American Samoa
AT|Austria
AU|Australia
AW|Aruba
AX|Aland Islands
AZ|Azerbaijan
BA|Bosnia and Herzegovina
BB|Barbados
BD|Bangladesh
BE|Belgium
BF|Burkina Faso
BG|Bulgaria
BH|Bahrain
BI|Burundi
BJ|Benin
BL|Saint Barthelemy
BM|Bermuda
BN|Brunei Darussalam
BO|Bolivia
BQ|Bonaire
BR|Brazil
BS|Bahamas
BT|Bhutan
BV|Bouvet Island
BW|Botswana
BY|Belarus
BZ|Belize
CA|Canada
CC|Cocos (Keeling) Islands
CD|Congo - Kinshasa
CF|Central African Republic
CG|Congo - Brazzaville
CH|Switzerland
CI|Cote D'Ivoire
CK|Cook Islands
CL|Chile
CM|Cameroon
CN|China
CO|Colombia
CR|Costa Rica
CU|Cuba
CV|Cape Verde
CW|Curacao
CX|Christmas Island
CY|Cyprus
CZ|Czech Republic
DE|Germany
DJ|Djibouti
DK|Denmark
DM|Dominica
DO|Dominican Republic
DZ|Algeria
EC|Ecuador
EE|Estonia
EG|Egypt
EH|Western Sahara
ER|Eritrea
ES|Spain
ET|Ethiopia
EU|Europe
FI|Finland
FJ|Fiji
FK|Falkland Islands (Malvinas)
FM|Micronesia
FO|Faroe Islands
FR|France
FX|Metropolitan France
GA|Gabon
GB|United Kingdom
GD|Grenada
GE|Georgia
GF|French Guiana
GG|Guernsey
GH|Ghana
GI|Gibraltar
GL|Greenland
GM|Gambia
GN|Guinea
GP|Guadeloupe
GQ|Equatorial Guinea
GR|Greece
GS|South Georgia and the South Sandwich Islands
GT|Guatemala
GU|Guam
GW|Guinea-Bissau
GY|Guyana
HK|Hong Kong
HM|Heard Island and McDonald Islands
HN|Honduras
HR|Croatia
HT|Haiti
HU|Hungary
ID|Indonesia
IE|Ireland
IL|Israel
IM|Isle of Man
IN|India
IO|British Indian Ocean Territory
IQ|Iraq
IR|Iran
IS|Iceland
IT|Italy
JE|Jersey
JM|Jamaica
JO|Jordan
JP|Japan
KE|Kenya
KG|Kyrgyzstan
KH|Cambodia
KI|Kiribati
KM|Comoros
KN|Saint Kitts and Nevis
KP|North Korea
KR|South Korea
KW|Kuwait
KY|Cayman Islands
KZ|Kazakhstan
LA|Lao People's Democratic Republic
LB|Lebanon
LC|Saint Lucia
LI|Liechtenstein
LK|Sri Lanka
LR|Liberia
LS|Lesotho
LT|Lithuania
LU|Luxembourg
LV|Latvia
LY|Libya
MA|Morocco
MC|Monaco
MD|Moldova
ME|Montenegro
MF|Saint Martin
MG|Madagascar
MH|Marshall Islands
MK|Macedonia
ML|Mali
MM|Myanmar
MN|Mongolia
MO|Macau
MP|Northern Mariana Islands
MQ|Martinique
MR|Mauritania
MS|Montserrat
MT|Malta
MU|Mauritius
MV|Maldives
MW|Malawi
MX|Mexico
MY|Malaysia
MZ|Mozambique
NA|Namibia
NC|New Caledonia
NE|Niger
NF|Norfolk Island
NG|Nigeria
NI|Nicaragua
NL|Netherlands
NO|Norway
NP|Nepal
NR|Nauru
NU|Niue
NZ|New Zealand
OM|Oman
PA|Panama
PE|Peru
PF|French Polynesia
PG|Papua New Guinea
PH|Philippines
PK|Pakistan
PL|Poland
PM|Saint Pierre and Miquelon
PN|Pitcairn Islands
PR|Puerto Rico
PS|Palestinian Territory
PT|Portugal
PW|Palau
PY|Paraguay
QA|Qatar
RE|Reunion
RO|Romania
RS|Serbia
RU|Russian Federation
RW|Rwanda
SA|Saudi Arabia
SB|Solomon Islands
SC|Seychelles
SD|Sudan
SE|Sweden
SG|Singapore
SH|Saint Helena
SI|Slovenia
SJ|Svalbard and Jan Mayen
SK|Slovakia
SL|Sierra Leone
SM|San Marino
SN|Senegal
SO|Somalia
SR|Suriname
SS|South Sudan
ST|Sao Tome and Principe
SV|El Salvador
SX|Sint Maarten (Dutch part)
SY|Syrian Arab Republic
SZ|Swaziland
TC|Turks and Caicos Islands
TD|Chad
TF|French Southern Territories
TG|Togo
TH|Thailand
TJ|Tajikistan
TK|Tokelau
TL|Timor-Leste
TM|Turkmenistan
TN|Tunisia
TO|Tonga
TR|Turkey
TT|Trinidad and Tobago
TV|Tuvalu
TW|Taiwan
TZ|Tanzania
UA|Ukraine
UG|Uganda
UM|United States Minor Outlying Islands
US|United States
UY|Uruguay
UZ|Uzbekistan
VA|Holy See (Vatican City State)
VC|Saint Vincent and the Grenadines
VE|Venezuela
VG|British Virgin Islands
VI|U.S. Virgin Islands
VN|Vietnam
VU|Vanuatu
WF|Wallis and Futuna
WS|Samoa
XK|Kosovo
YE|Yemen
YT|Mayotte
ZA|South Africa
ZM|Zambia
ZW|Zimbabwe
EOF

# helper functions

sub usage {
    say STDERR "Sophos Migration Utility CLI for UTM to SFOS - Version $VERSION";
    say STDERR "USAGE: $0 [-i path/to/snapshot] [-o path/to/Export.tar] [-d]";
    say STDERR "\t-i\t- Path to a specific UTM snapshot to be exported.\n\t\t  Usually located in /var/confd/var/storage/snapshots/";
    say STDERR "\t\t  If -i is not specified, a snapshot of the current UTM configuration will be created and used.";
    say STDERR "\t-o\t- Optional export path for the SFOS compatible TAR file.\n\t\t  Default: ./Export.tar";
    say STDERR "\t-d\t- Optional debug output; repeat for higher verbosity (-dd enables validation failure reasons)\n\t\t  Default: off";
    say STDERR "\t-s\t- Optional template name to only export a single template type to STDOUT. For development purposes only.";
    say STDERR "\t-p\t- Optional SFOS interface name for VPN local interface defaults.\n\t\t  Default: $DEFAULT_INTERFACE_NAME";
    say STDERR "\t-D\t- Optional SFOS interface name for DHCP fallback when source interface labels are not SFOS-compatible.\n\t\t  Default: $DEFAULT_DHCP_INTERFACE_NAME";
    say STDERR "\t-h\t- Display this help / usage message.";
    say STDERR "\t-l\t- Optional flag to force Enable firewall-rule log settings\n\t\t  Default: follow source rule log setting";
    say STDERR "\t-F\t- Optional flag to disable migration of firewall rules\n\t\t  Default: off";
    say STDERR "\t-I\t- Optional fallback interface name for static interface routes (e.g., Port1)\n\t\t  Default: Port1";
    say STDERR "\t\t  If not specified, interface routes use the default interface.";
    say STDERR "\t-N\t- NAT strategy mode: safe|compat\n\t\t  Default: compat";
    say STDERR "\t-R\t- Optional path to write migration report JSON\n\t\t  Default: <output>.report.json";
    say STDERR "Important: This tool is meant to be run on Sophos UTM / ASG systems. Usage on other systems may require you to";
    say STDERR "convert the snapshot file (see util/convert_snapshot.pl), and will require the -i option.";
    exit;
}

sub read_backup {
    my ($fn) = @_;
    -f $fn or die $!;
    return retrieve $fn;
}

sub ensure_arrayref {
    my ($value) = @_;
    return [] if !defined $value;
    return $value if ref($value) eq 'ARRAY';
    return [$value];
}

sub is_true {
    my ($value) = @_;
    return 0 if !defined $value;
    return 1 if $value eq '1' || $value eq 'on' || $value eq 'yes' || $value eq 'true';
    return 0;
}

sub bool_to_enable_disable {
    my ($value) = @_;
    return is_true($value) ? 'Enable' : 'Disable';
}

sub bool_to_on_off {
    my ($value) = @_;
    return is_true($value) ? 'on' : 'off';
}

sub parse_debug_level_from_argv {
    my ($argv) = @_;
    return 0 if ref($argv) ne 'ARRAY';

    my %opts_with_arg = map { $_ => 1 } qw(i o p D s N R I);
    my $level = 0;

    for (my $i = 0; $i <= $#$argv; $i++) {
        my $arg = $argv->[$i];
        next if !defined $arg;
        last if $arg eq '--';
        next if $arg !~ /^-([^-].*)$/;

        my $cluster = $1;
        my @chars = split //, $cluster;
        for (my $j = 0; $j <= $#chars; $j++) {
            my $ch = $chars[$j];
            $level++ if $ch eq 'd';

            if ($opts_with_arg{$ch}) {
                # Option argument starts here (possibly attached), stop scanning this token.
                if ($j == $#chars) {
                    $i++ if $i < $#$argv;
                }
                last;
            }
        }
    }

    return $level;
}

sub debug_validation_failure {
    my ($validator, $value, $reason) = @_;
    return if $DEBUG < 2;
    my $display = defined $value ? $value : '<undef>';
    $display =~ s/\s+/ /g;
    warn "[debug2][$validator] failed: $reason; value=\"$display\"\n";
}

sub format_warning_context {
    my ($context) = @_;
    return '' if ref($context) ne 'HASH' || !%$context;

    my @parts;
    for my $key (sort keys %$context) {
        my $value = $context->{$key};
        if (ref($value) eq 'ARRAY') {
            $value = join(',', @$value);
        } elsif (ref($value) eq 'HASH') {
            $value = JSON->new->canonical(1)->encode($value);
        } elsif (!defined $value) {
            $value = '';
        }
        $value =~ s/\s+/ /g;
        push @parts, "$key=$value";
    }

    return '' if !@parts;
    return ' {' . join(', ', @parts) . '}';
}

sub add_warning {
    my ($feature, $message, $context) = @_;
    push @{ $MIGRATION_REPORT{warnings} }, {
        feature => $feature,
        message => $message,
        context => $context // {},
    };
    my $details = format_warning_context($context // {});
    warn "[$feature] $message$details\n";
}

sub increment_stat {
    my ($key, $inc) = @_;
    $inc //= 1;
    $MIGRATION_REPORT{stats}{$key} //= 0;
    $MIGRATION_REPORT{stats}{$key} += $inc;
}

sub build_migration_report_json {
    my $json = JSON->new->pretty->canonical(1);
    return $json->encode(\%MIGRATION_REPORT);
}

sub names_for_refs {
    my ($backup, $refs, $resolver) = @_;
    my @ret;
    for my $ref (@{ensure_arrayref($refs)}) {
        my $obj = get_ref($backup, $ref);
        next if !$obj;
        my $name;
        if ($resolver) {
            $name = $resolver->($obj);
        }
        $name //= $obj->{data}->{name};
        next if !defined $name || $name eq '';
        push @ret, $name;
    }
    return \@ret;
}

sub exported_schedule_name {
    my ($name) = @_;
    return escape_trunc($name, 50);
}

sub parse_one_host_group {
    my ($backup, $obj) = @_;
    my ($ip_member_names, $fqdn_member_names) = classify_host_group_members($backup, $obj);
    if (!@$ip_member_names) {
        my $has_fqdn_members = scalar @$fqdn_member_names;
        add_warning('host-group', 'Skipping IPHostGroup export because no IPHost-compatible members were found', {
            group => $obj->{data}->{name} // $obj->{ref},
            fqdn_members => $has_fqdn_members,
        });
        return [];
    }
    return [{
        name => escape_trunc("Net Group: ".$obj->{data}->{name}),
        description => $obj->{data}->{comment},
        group => 1,
        family => 'IPv4',
        hosts => [ map { { name => $_ } } @$ip_member_names ],
    }];
}

sub classify_host_group_members {
    my ($backup, $obj, $opts) = @_;
    my $suppress_nested_warning = (ref($opts) eq 'HASH' && $opts->{suppress_nested_warning}) ? 1 : 0;
    my @ip_member_names;
    my @fqdn_member_names;

    for my $member_ref (@{ensure_arrayref($obj->{data}->{members})}) {
        my $member_obj = get_ref($backup, $member_ref);
        next if !$member_obj;

        my $class_type = $member_obj->{class} . '/' . $member_obj->{type};
        if ($class_type eq 'network/group') {
            if (!$suppress_nested_warning) {
                add_warning('host-group', 'Skipping nested network group member because SFOS host-group members must reference concrete host entities', {
                    group => $obj->{data}->{name} // $obj->{ref},
                    member_ref => $member_ref,
                });
            }
            next;
        }

        my $parsed = parse_one_host($backup, $member_obj);
        next if ref($parsed) ne 'ARRAY';

        if ($class_type eq 'network/dns_host' || $class_type eq 'network/dns_group') {
            push @fqdn_member_names, map { $_->{name} }
                grep { $_->{fqdn} && defined $_->{name} && $_->{name} ne '' } @$parsed;
            next;
        }

        push @ip_member_names, map { $_->{name} }
            grep {
                defined $_->{name}
                && $_->{name} ne ''
                && !$_->{fqdn}
                && !$_->{maclist}
                && !$_->{iplist}
            } @$parsed;
    }

    my %seen_ip;
    @ip_member_names = grep { !$seen_ip{$_}++ } @ip_member_names;
    my %seen_fqdn;
    @fqdn_member_names = grep { !$seen_fqdn{$_}++ } @fqdn_member_names;

    return (\@ip_member_names, \@fqdn_member_names);
}

sub parse_fqdn_host_groups {
    my ($backup) = @_;
    my @ret;

    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        my $group_data = parse_one_fqdn_host_group($backup, $obj);
        next if ref($group_data) ne 'ARRAY' || !@$group_data;
        push @ret, @$group_data;
    }

    return \@ret;
}

sub parse_one_fqdn_host_group {
    my ($backup, $obj) = @_;
    return [] if !$obj || $obj->{class} ne 'network' || $obj->{type} ne 'group';

    my ($ip_member_names, $fqdn_member_names) = classify_host_group_members($backup, $obj);
    return [] if !@$fqdn_member_names;

    return [{
        group => 1,
        name => escape_trunc("Net Group: ".$obj->{data}->{name}),
        description => $obj->{data}->{comment},
        hosts => [ map { { name => $_ } } @$fqdn_member_names ],
    }];
}

sub project_network_object_entries {
    my ($backup, $network_obj) = @_;
    my @entries;
    return \@entries if !$network_obj || ref($network_obj) ne 'HASH';

    if (($network_obj->{data}->{name} // '') eq 'Internet IPv4') {
        push @entries, { name => 'Internet IPv4 group', kind => 'ip_group' };
        return \@entries;
    }

    my $parsed = parse_one_host($backup, $network_obj);
    if (ref($parsed) eq 'ARRAY') {
        for my $row (@$parsed) {
            next if ref($row) ne 'HASH';
            my $name = $row->{name} // '';
            next if $name eq '';
            my $kind = 'ip';
            $kind = 'fqdn' if $row->{fqdn};
            $kind = 'mac' if $row->{maclist};
            push @entries, { name => $name, kind => $kind };
        }
    }

    if (defined $network_obj->{data}->{members}) {
        my ($ip_member_names, $fqdn_member_names) = classify_host_group_members($backup, $network_obj, { suppress_nested_warning => 1 });
        my $group_name = escape_trunc("Net Group: ".$network_obj->{data}->{name});
        push @entries, { name => $group_name, kind => 'ip_group' } if @$ip_member_names;
        push @entries, { name => $group_name, kind => 'fqdn_group' } if @$fqdn_member_names;
    }

    my %seen;
    @entries = grep { !$seen{($_->{kind} // '') . "\x1e" . ($_->{name} // '')}++ } @entries;
    return \@entries;
}

sub ref_to_network_entries {
    my ($backup, $ref) = @_;
    return [] if !defined $ref || $ref eq '';
    my $obj = get_ref($backup, $ref);
    return [] if !$obj;
    return project_network_object_entries($backup, $obj);
}

sub ref_to_network_names {
    my ($backup, $ref, %opts) = @_;
    my $entries = ref_to_network_entries($backup, $ref);
    my %allowed_kind = (
        ip => 1,
        fqdn => 1,
        ip_group => 1,
        fqdn_group => 1,
        mac => ($opts{include_mac} ? 1 : 0),
    );

    my @names = map { $_->{name} }
        grep { $allowed_kind{$_->{kind} // ''} && defined $_->{name} && $_->{name} ne '' }
        @$entries;
    my %seen;
    @names = grep { !$seen{$_}++ } @names;
    return \@names;
}

sub is_ipv6_firewall_network_name {
    my ($name) = @_;
    return 0 if !defined $name || $name eq '';
    return 1 if $name eq 'Any IPv6';
    return 1 if $name =~ /^(?:Host IPv6:|Network IPv6:|Range IPv6:)/;
    return 0;
}

sub finalize_ipv4_firewall_networks {
    my ($rule_name, $field, $rows) = @_;
    my @filtered;
    my @dropped_ipv6;
    for my $row (@{ensure_arrayref($rows)}) {
        next if ref($row) ne 'HASH';
        my $name = $row->{name};
        next if !defined $name || $name eq '';
        if (is_ipv6_firewall_network_name($name)) {
            push @dropped_ipv6, $name;
            next;
        }
        push @filtered, { name => $name };
    }

    my %seen;
    @filtered = grep { !$seen{$_->{name}}++ } @filtered;

    if (@dropped_ipv6) {
        my %seen_dropped;
        @dropped_ipv6 = grep { !$seen_dropped{$_}++ } @dropped_ipv6;
        add_warning('firewall', 'Dropped IPv6 network references from IPv4 firewall rule export to satisfy SFOS source/destination family validation', {
            rule => $rule_name,
            field => $field,
            dropped_networks => \@dropped_ipv6,
        });
        increment_stat('firewall.ipv6_candidates_dropped', scalar @dropped_ipv6);
    }

    if (grep { $_->{name} eq 'Any' || $_->{name} eq 'Any IPv4' || $_->{name} eq 'Any IPv6' } @filtered) {
        return [];
    }

    return \@filtered;
}

sub refs_to_network_names {
    my ($backup, $refs, %opts) = @_;
    my @names;
    for my $ref (@{ensure_arrayref($refs)}) {
        push @names, @{ ref_to_network_names($backup, $ref, %opts) };
    }
    my %seen;
    @names = grep { !$seen{$_}++ } @names;
    return \@names;
}

sub resolve_atp_host_exception_names {
    my ($backup, $ref) = @_;
    return [] if !defined $ref || $ref eq '';

    my $names = ref_to_network_names($backup, $ref);
    return $names if @$names;

    my $obj = get_ref($backup, $ref);
    return [] if !$obj || ref($obj) ne 'HASH';
    my @fallback_refs;
    if (($obj->{class} // '') eq 'itfparams' && ($obj->{type} // '') eq 'primary') {
        push @fallback_refs, ($obj->{data}->{primary_address} // '');
    } elsif (($obj->{class} // '') eq 'network' && ($obj->{type} // '') eq 'interface_network') {
        my $data = $obj->{data} // {};
        push @fallback_refs,
            ($data->{interface_address} // ''),
            ($data->{primary_address} // ''),
            ($data->{address_ref} // '');

        my $objects = $backup->{objects};
        if (ref($objects) eq 'HASH') {
            for my $candidate (values %$objects) {
                next if !$candidate || ref($candidate) ne 'HASH';
                next if ($candidate->{class} // '') ne 'itfparams' || ($candidate->{type} // '') ne 'primary';
                my $candidate_data = $candidate->{data};
                next if ref($candidate_data) ne 'HASH';

                my $references_network = grep {
                    defined $_ && !ref($_) && $_ eq $ref
                } values %$candidate_data;
                next if !$references_network;

                push @fallback_refs,
                    ($candidate_data->{primary_address} // ''),
                    ($candidate_data->{interface_address} // '');
            }
        }
    }

    my %seen_ref;
    for my $fallback_ref (@fallback_refs) {
        next if !defined $fallback_ref || $fallback_ref eq '' || $fallback_ref eq $ref;
        next if $seen_ref{$fallback_ref}++;
        my $fallback_names = ref_to_network_names($backup, $fallback_ref);
        return $fallback_names if @$fallback_names;
    }

    return [];
}

sub ref_to_preferred_network_name {
    my ($backup, $ref, %opts) = @_;
    my $entries = ref_to_network_entries($backup, $ref);
    return '' if !@$entries;

    my @kind_priority = (
        qw(ip ip_group fqdn fqdn_group mac)
    );
    if (($opts{prefer} // '') eq 'fqdn_first') {
        @kind_priority = (qw(fqdn fqdn_group ip ip_group mac));
    }
    for my $kind (@kind_priority) {
        for my $entry (@$entries) {
            next if ($entry->{kind} // '') ne $kind;
            return $entry->{name} // '';
        }
    }
    return $entries->[0]->{name} // '';
}

sub enrich_host_template_data {
    my ($template_data, $obj) = @_;
    my @rows = ref($template_data) eq 'ARRAY' ? @$template_data : ($template_data);
    my $description = escape_html($obj->{data}->{comment} // '');

    for my $row (@rows) {
        next if ref($row) ne 'HASH';
        $row->{description} = $description;

        my $row_name = $row->{name} // '';
        next if $row_name eq '';

        # Do not emit back-references from Host to HostGroup (Host.hostgroupid). HostGroup membership
        # is exported via HostGroup.select, and emitting both directions can create circular import dependencies.
    }

    return ref($template_data) eq 'ARRAY' ? \@rows : $rows[0];
}

sub parse_service_group {
    my ($backup, $obj) = @_;
    my @services = map { { name => escape_trunc($backup->{objects}->{$_}->{data}->{name}) } } @{$obj->{data}->{members}};
    return {
        servicegroup_name => escape_trunc($obj->{data}->{name}),
        description => escape_trunc($obj->{data}->{comment}),
        services => \@services,
    }
}

sub get_firewall_rule_position {
    my ($backup, $obj) = @_;
    my $rule_ref = $obj->{ref};

    my @rules = @{ensure_arrayref($backup->{main}->{packetfilter}->{rules})};
    if (!@rules) {
        return {
            position => 'Bottom',
            prev => '',
        };
    }
    my $idx = -1;
    for my $i (0 .. $#rules){
        if ($rules[$i] eq $rule_ref){
             $idx = $i;
             last;
        }
    }
    if ($idx == 0) {
        return {
            position => 'Bottom',
            prev => ''
        };
    }

    my $next_ref = $rules[$idx - 1];
    return {
        position => 'After',
        prev => escape_trunc($backup->{objects}->{$next_ref}->{data}->{name}),
    };
}

sub get_mac_names {
    my ($backup, $obj) = @_;
    my $ref = get_ref($backup, $obj);
    my @mac_names = ();
    if ($ref->{type} eq 'host') {
        my @ret = @{parse_one_host_from_host($backup, $ref)};
        foreach my $host_obj (@ret) {
            if (exists($host_obj->{maclist}) && $host_obj->{maclist} eq 1) {
                push @mac_names, {name => $host_obj->{name}};
            }
        }
     }
     return \@mac_names;
}

sub parse_firewall_rule {
    if (! $MIGRATE_FIREWALL_RULES) {
        return {};
    }
    my ($backup, $obj) = @_;
    my $rule_name = escape_trunc($obj->{data}->{name});
    my $location = get_firewall_rule_position($backup, $obj);
    my @services = map { { name => $backup->{objects}->{$_}->{data}->{name} } } @{ensure_arrayref($obj->{data}->{services})};
    if (grep { $_->{ name } eq 'Any' } @services) {
        @services = ();
    }

    my @sources = ();
    foreach my $network_ref (@{ensure_arrayref($obj->{data}->{sources})}) {
        push @sources, map { { name => $_ } } @{ ref_to_network_names($backup, $network_ref) };
    }

    if ($obj->{data}->{source_mac_addresses}) {
        my @mac_networks = @{ get_ref($backup, $obj->{data}->{source_mac_addresses})->{data}->{host_list}};
        foreach my $network_ref (@mac_networks) {
            my @mac_names = @{get_mac_names($backup, $network_ref)};
            foreach my $mac_name (@mac_names) {
                push @sources, $mac_name;
            }
        }
    }
    @sources = @{ finalize_ipv4_firewall_networks($rule_name, 'SourceNetworks', \@sources) };

    my @destinations = ();
    foreach my $network_ref (@{ensure_arrayref($obj->{data}->{destinations})}) {
        push @destinations, map { { name => $_ } } @{ ref_to_network_names($backup, $network_ref) };
    }
    @destinations = @{ finalize_ipv4_firewall_networks($rule_name, 'DestinationNetworks', \@destinations) };

    @services = map { { name => escape_trunc($_->{name}) } } @{services};

    my %action_map = (
        accept => 'Accept',
        drop => 'Drop',
        reject => 'Reject',
    );
    my $mapped_action = $action_map{ lc($obj->{data}->{action} // '') } // $obj->{data}->{action};

    my $dscp_marking = '';
    if ($obj->{type} eq 'mangle') {
        # UTM mangle rules might clear DF or do other things.
        # Try to extract DSCP if present.
        $dscp_marking = $obj->{data}->{dscp_value} // $obj->{data}->{dscp} // '';
    }

    return {
        rule_name => $rule_name,
        description => escape_html($obj->{data}->{comment}),
        status => ($obj->{data}->{status} ? 'Enable' : 'Disable'),
        action => $mapped_action,
        logtraffic => ($LOG_FIREWALL ? 'Enable' : ($obj->{data}->{log} ? 'Enable' : 'Disable')),
        dscp_marking => $dscp_marking,
        position => $location->{position},
        position_name => ($location->{position} eq 'Bottom' ? undef : $location->{prev}),
        services => \@services,
        sources => \@sources,
        destinations => \@destinations,
        policy_type => 'Network',
    };
}

sub sfos_geoip_country_hostnames_by_code {
    state $map;
    return $map if defined $map;

    my %ret;
    for my $line (split /\n/, $SFOS_GEOIP_COUNTRY_HOSTMAP_DATA) {
        next if !defined $line || $line =~ /^\s*$/;
        my ($code, $name) = split(/\|/, $line, 2);
        next if !defined $code || !defined $name;
        $code =~ s/^\s+|\s+$//g;
        $name =~ s/^\s+|\s+$//g;
        next if $code eq '' || $name eq '';
        $ret{uc($code)} = $name;
    }
    $map = \%ret;
    return $map;
}

sub geoip_hash_suffix {
    my ($seed) = @_;
    $seed //= '';
    return uc(substr(md5_hex($seed), 0, 8));
}

sub geoip_group_name {
    my ($label, $seed) = @_;
    return escape_trunc("SMU GEOIP $label " . geoip_hash_suffix($seed), 50);
}

sub geoip_rule_name {
    my ($label, $seed) = @_;
    return escape_trunc("SMU GEOIP $label " . geoip_hash_suffix($seed), 50);
}

sub normalize_geoip_country_codes {
    my ($codes, $context) = @_;
    my @ret;
    my %seen;
    my %ctx = ref($context) eq 'HASH' ? %$context : ();

    for my $raw (@{ ensure_arrayref($codes) }) {
        next if !defined $raw;
        my $code = uc($raw);
        $code =~ s/^\s+|\s+$//g;
        next if $code eq '';
        if ($code !~ /^[A-Z]{2}$/) {
            add_warning('geoip', 'Skipping GEOIP country entry because it is not a two-letter ISO code', {
                %ctx,
                country => $raw,
            });
            increment_stat('geoip.country.invalid');
            next;
        }
        next if $seen{$code}++;
        push @ret, $code;
    }
    return \@ret;
}

our %GEOIP_DEPRECATED_COUNTRY_CODE_MAP = (
    AN => [qw(BQ CW SX)],
);

our %GEOIP_UNSUPPORTED_COUNTRY_CODES = map { $_ => 1 } qw(BV HM);

sub geoip_country_names_for_codes {
    my ($codes, $context) = @_;
    my @ret;
    my %seen;
    my %ctx = ref($context) eq 'HASH' ? %$context : ();
    my $map = sfos_geoip_country_hostnames_by_code();

    for my $code (@{ ensure_arrayref($codes) }) {
        next if !defined $code || $code eq '';

        if ($GEOIP_UNSUPPORTED_COUNTRY_CODES{$code}) {
            add_warning('geoip', 'Skipping GEOIP country code because no SFOS-compatible mapping exists', {
                %ctx,
                country => $code,
            });
            increment_stat('geoip.country.unsupported');
            next;
        }

        my @effective_codes = ($code);
        if (ref($GEOIP_DEPRECATED_COUNTRY_CODE_MAP{$code}) eq 'ARRAY') {
            @effective_codes = @{ $GEOIP_DEPRECATED_COUNTRY_CODE_MAP{$code} };
            add_warning('geoip', 'Remapping deprecated GEOIP country code to SFOS-supported successor country codes', {
                %ctx,
                country => $code,
                remapped_to => join(',', @effective_codes),
            });
            increment_stat('geoip.country.remapped');
        }

        for my $effective_code (@effective_codes) {
            my $name = $map->{$effective_code};
            if (!defined $name || $name eq '') {
                add_warning('geoip', 'Skipping GEOIP country code because no SFOS CountryHost name mapping exists', {
                    %ctx,
                    country => $effective_code,
                    source_country => $code,
                });
                increment_stat('geoip.country.unmapped');
                next;
            }
            next if $seen{$name}++;
            push @ret, $name;
        }
    }
    return \@ret;
}

sub geoip_country_group_template_data {
    my (%args) = @_;
    my @country_names = @{ ensure_arrayref($args{country_names}) };
    return undef if !@country_names;
    return {
        name => escape_trunc($args{name} // '', 50),
        description => escape_html($args{description} // ''),
        countries => [ map { { name => escape_trunc($_, 50) } } @country_names ],
    };
}

sub geoip_register_country_group {
    my ($groups, $group_seen, %args) = @_;
    my $name = $args{name} // '';
    return '' if $name eq '';
    if (!$group_seen->{$name}) {
        my $data = geoip_country_group_template_data(
            name => $name,
            description => $args{description},
            country_names => $args{country_names},
        );
        return '' if !defined $data;
        push @$groups, $data;
        $group_seen->{$name} = 1;
    }
    return $name;
}

sub geoip_service_rows_from_refs {
    my ($backup, $refs) = @_;
    my @service_names;
    for my $ref (@{ ensure_arrayref($refs) }) {
        my $service_name = ref_to_service_name($backup, $ref);
        next if $service_name eq '';
        push @service_names, $service_name;
    }
    my %seen;
    @service_names = grep { !$seen{$_}++ } @service_names;
    return [ map { { name => $_ } } @service_names ];
}

sub geoip_network_rows_from_refs {
    my ($backup, $rule_name, $field_name, $refs) = @_;
    my @names = @{ refs_to_network_names($backup, $refs) };
    my @rows = map { { name => $_ } } @names;
    return finalize_ipv4_firewall_networks($rule_name, $field_name, \@rows);
}

sub geoip_network_refs_imply_any {
    my ($backup, $refs) = @_;
    for my $ref (@{ ensure_arrayref($refs) }) {
        next if !defined $ref || $ref eq '';
        return 1 if $ref eq 'Any' || $ref eq 'Any IPv4' || $ref eq 'Any IPv6';

        my $obj = get_ref($backup, $ref);
        next if !$obj || ref($obj) ne 'HASH';
        return 1 if ($obj->{type} // '') eq 'any';

        my $data = $obj->{data};
        next if ref($data) ne 'HASH';
        return 1 if is_any_network($obj);
        return 1 if (defined $data->{address} && defined $data->{netmask} && $data->{address} eq '0.0.0.0' && $data->{netmask} == 0);
        return 1 if (defined $data->{address6} && defined $data->{netmask6} && $data->{address6} eq '::' && $data->{netmask6} == 0);
    }
    return 0;
}

sub geoip_cache_signature {
    my ($backup) = @_;
    my $main = ref($backup->{main}) eq 'HASH' ? $backup->{main} : {};
    my $geoip = ref($main->{geoip}) eq 'HASH' ? $main->{geoip} : {};

    my %signature = (
        status => $geoip->{status} // '',
        log => $geoip->{log} // '',
        countries_src => [ @{ ensure_arrayref($geoip->{countries_src}) } ],
        countries_dst => [ @{ ensure_arrayref($geoip->{countries_dst}) } ],
        exceptions => [],
    );

    for my $exception_ref (@{ ensure_arrayref($geoip->{exceptions}) }) {
        my $obj = get_ref($backup, $exception_ref);
        my $data = (ref($obj) eq 'HASH' && ref($obj->{data}) eq 'HASH') ? $obj->{data} : {};
        push @{ $signature{exceptions} }, {
            ref => $exception_ref,
            class => (ref($obj) eq 'HASH' ? ($obj->{class} // '') : ''),
            type => (ref($obj) eq 'HASH' ? ($obj->{type} // '') : ''),
            status => $data->{status} // '',
            name => $data->{name} // '',
            countries => [ @{ ensure_arrayref($data->{countries}) } ],
            source_networks => [ @{ ensure_arrayref($data->{source_networks}) } ],
            destination_networks => [ @{ ensure_arrayref($data->{destination_networks}) } ],
            services => [ @{ ensure_arrayref($data->{services}) } ],
        };
    }

    my $json = JSON->new->canonical(1);
    return md5_hex($json->encode(\%signature));
}

sub build_geoip_migration_artifacts {
    my ($backup) = @_;
    my $empty = { country_groups => [], firewall_rules => [] };
    return $empty if ref($backup) ne 'HASH';

    my $signature = geoip_cache_signature($backup);
    if (
        ref($backup->{_smu_geoip_cache}) eq 'HASH'
        && ($backup->{_smu_geoip_cache_signature} // '') eq $signature
    ) {
        return $backup->{_smu_geoip_cache};
    }

    my $main = $backup->{main};
    if (ref($main) ne 'HASH' || ref($main->{geoip}) ne 'HASH') {
        $backup->{_smu_geoip_cache} = $empty;
        $backup->{_smu_geoip_cache_signature} = $signature;
        return $backup->{_smu_geoip_cache};
    }

    my $geoip = $main->{geoip};
    my $has_geoip_payload =
        scalar(@{ ensure_arrayref($geoip->{countries_src}) })
        || scalar(@{ ensure_arrayref($geoip->{countries_dst}) })
        || scalar(@{ ensure_arrayref($geoip->{exceptions}) });

    if (!is_true($geoip->{status})) {
        if ($has_geoip_payload) {
            add_warning('geoip', 'UTM GEOIP is disabled; skipping CountryGroup and GEOIP firewall migration output');
            increment_stat('geoip.skipped.disabled');
        }
        $backup->{_smu_geoip_cache} = $empty;
        $backup->{_smu_geoip_cache_signature} = $signature;
        return $backup->{_smu_geoip_cache};
    }

    my @country_groups;
    my @firewall_rules;
    my %country_group_seen;

    my $src_codes = normalize_geoip_country_codes($geoip->{countries_src}, {
        section => 'countries_src',
    });
    my $dst_codes = normalize_geoip_country_codes($geoip->{countries_dst}, {
        section => 'countries_dst',
    });
    my $src_country_names = geoip_country_names_for_codes($src_codes, {
        section => 'countries_src',
    });
    my $dst_country_names = geoip_country_names_for_codes($dst_codes, {
        section => 'countries_dst',
    });

    my $src_group_name = '';
    if (@$src_country_names) {
        $src_group_name = geoip_group_name('SRC BLOCK', 'src-block|' . join(',', @$src_codes));
        $src_group_name = geoip_register_country_group(
            \@country_groups,
            \%country_group_seen,
            name => $src_group_name,
            description => 'Generated from UTM GEOIP source-country block list',
            country_names => $src_country_names,
        );
    }

    my $dst_group_name = '';
    if (@$dst_country_names) {
        $dst_group_name = geoip_group_name('DST BLOCK', 'dst-block|' . join(',', @$dst_codes));
        $dst_group_name = geoip_register_country_group(
            \@country_groups,
            \%country_group_seen,
            name => $dst_group_name,
            description => 'Generated from UTM GEOIP destination-country block list',
            country_names => $dst_country_names,
        );
    }

    my $block_log_mode = lc($geoip->{log} // 'limited');
    my $block_logtraffic = ($block_log_mode eq 'off') ? 'Disable' : 'Enable';

    for my $exception_ref (@{ ensure_arrayref($geoip->{exceptions}) }) {
        next if !defined $exception_ref || $exception_ref eq '';
        my $exception_obj = get_ref($backup, $exception_ref);
        if (!$exception_obj || ref($exception_obj->{data}) ne 'HASH') {
            add_warning('geoip', 'Skipping GEOIP exception reference because object could not be resolved', {
                exception_ref => $exception_ref,
            });
            increment_stat('geoip.exception.skipped.unresolved');
            next;
        }
        my $exception_type = $exception_obj->{type} // '';
        if ($exception_obj->{class} ne 'geoip' || ($exception_type ne 'srcexception' && $exception_type ne 'dstexception')) {
            add_warning('geoip', 'Skipping GEOIP exception reference because class/type is unsupported for migration', {
                exception_ref => $exception_ref,
                class_type => ($exception_obj->{class} // '') . '/' . $exception_type,
            });
            increment_stat('geoip.exception.skipped.unsupported');
            next;
        }

        my $exception_data = $exception_obj->{data};
        next if !is_true($exception_data->{status});

        my $seed_label = ($exception_type eq 'srcexception') ? 'EXC SRC' : 'EXC DST';
        my $rule_name = geoip_rule_name($seed_label, $exception_ref);

        my $services = geoip_service_rows_from_refs($backup, $exception_data->{services});
        my $sources = [];
        my $destinations = [];

        if ($exception_type eq 'srcexception') {
            my $sources_any = geoip_network_refs_imply_any($backup, $exception_data->{source_networks});
            $sources = geoip_network_rows_from_refs($backup, $rule_name, 'SourceNetworks', $exception_data->{source_networks});
            if (!@$sources && !$sources_any) {
                add_warning('geoip', 'Skipping source GEOIP exception because no SFOS-compatible source networks were derived', {
                    exception_ref => $exception_ref,
                });
                increment_stat('geoip.exception.skipped.no_source');
                next;
            }
            my $codes = normalize_geoip_country_codes($exception_data->{countries}, {
                section => 'srcexception.countries',
                exception_ref => $exception_ref,
            });
            if (@$codes) {
                my $country_names = geoip_country_names_for_codes($codes, {
                    section => 'srcexception.countries',
                    exception_ref => $exception_ref,
                });
                if (!@$country_names) {
                    add_warning('geoip', 'Skipping source GEOIP exception because countries were configured but no SFOS CountryHost names were mapped', {
                        exception_ref => $exception_ref,
                    });
                    increment_stat('geoip.exception.skipped.country_mapping');
                    next;
                }
                my $exception_group_name = geoip_group_name('EXC SRC', $exception_ref . '|countries|' . join(',', @$codes));
                $exception_group_name = geoip_register_country_group(
                    \@country_groups,
                    \%country_group_seen,
                    name => $exception_group_name,
                    description => 'Generated from UTM GEOIP source-exception country list',
                    country_names => $country_names,
                );
                push @$destinations, { name => $exception_group_name } if $exception_group_name ne '';
            }
        } else {
            my $destinations_any = geoip_network_refs_imply_any($backup, $exception_data->{destination_networks});
            $destinations = geoip_network_rows_from_refs($backup, $rule_name, 'DestinationNetworks', $exception_data->{destination_networks});
            if (!@$destinations && !$destinations_any) {
                add_warning('geoip', 'Skipping destination GEOIP exception because no SFOS-compatible destination networks were derived', {
                    exception_ref => $exception_ref,
                });
                increment_stat('geoip.exception.skipped.no_destination');
                next;
            }
            my $codes = normalize_geoip_country_codes($exception_data->{countries}, {
                section => 'dstexception.countries',
                exception_ref => $exception_ref,
            });
            if (@$codes) {
                my $country_names = geoip_country_names_for_codes($codes, {
                    section => 'dstexception.countries',
                    exception_ref => $exception_ref,
                });
                if (!@$country_names) {
                    add_warning('geoip', 'Skipping destination GEOIP exception because countries were configured but no SFOS CountryHost names were mapped', {
                        exception_ref => $exception_ref,
                    });
                    increment_stat('geoip.exception.skipped.country_mapping');
                    next;
                }
                my $exception_group_name = geoip_group_name('EXC DST', $exception_ref . '|countries|' . join(',', @$codes));
                $exception_group_name = geoip_register_country_group(
                    \@country_groups,
                    \%country_group_seen,
                    name => $exception_group_name,
                    description => 'Generated from UTM GEOIP destination-exception country list',
                    country_names => $country_names,
                );
                push @$sources, { name => $exception_group_name } if $exception_group_name ne '';
            }
        }

        push @firewall_rules, {
            rule_name => $rule_name,
            description => escape_html('Generated from UTM GEOIP exception ' . ($exception_data->{name} // $exception_ref)),
            status => 'Enable',
            action => 'Accept',
            logtraffic => 'Disable',
            services => $services,
            sources => $sources,
            destinations => $destinations,
            policy_type => 'Network',
        };
    }

    if ($src_group_name ne '') {
        push @firewall_rules, {
            rule_name => geoip_rule_name('BLOCK SRC', 'block-src|' . $src_group_name),
            description => escape_html('Generated from UTM GEOIP source-country blocking'),
            status => 'Enable',
            action => 'Drop',
            logtraffic => $block_logtraffic,
            services => [],
            sources => [{ name => $src_group_name }],
            destinations => [],
            policy_type => 'Network',
        };
    }

    if ($dst_group_name ne '') {
        push @firewall_rules, {
            rule_name => geoip_rule_name('BLOCK DST', 'block-dst|' . $dst_group_name),
            description => escape_html('Generated from UTM GEOIP destination-country blocking'),
            status => 'Enable',
            action => 'Drop',
            logtraffic => $block_logtraffic,
            services => [],
            sources => [],
            destinations => [{ name => $dst_group_name }],
            policy_type => 'Network',
        };
    }

    my $prev_name = '';
    for my $idx (0 .. $#firewall_rules) {
        my $rule = $firewall_rules[$idx];
        if ($idx == 0) {
            $rule->{position} = 'Top';
            delete $rule->{position_name};
        } else {
            $rule->{position} = 'After';
            $rule->{position_name} = $prev_name;
        }
        $prev_name = $rule->{rule_name};
    }

    increment_stat('geoip.country_group', scalar @country_groups) if @country_groups;
    increment_stat('geoip.firewall_rule', scalar @firewall_rules) if @firewall_rules;

    my $ret = {
        country_groups => \@country_groups,
        firewall_rules => \@firewall_rules,
    };
    $backup->{_smu_geoip_cache} = $ret;
    $backup->{_smu_geoip_cache_signature} = $signature;
    return $ret;
}

sub parse_geoip_country_groups {
    my ($backup) = @_;
    my $artifacts = build_geoip_migration_artifacts($backup);
    return $artifacts->{country_groups} // [];
}

sub parse_geoip_firewall_rules {
    my ($backup) = @_;
    my $artifacts = build_geoip_migration_artifacts($backup);
    return $artifacts->{firewall_rules} // [];
}

sub cidr_to_netmask {
    my ($cidr) = @_;
    return join '.', unpack 'C4', pack 'N', (2**$cidr-1) << (32 - $cidr);
}

sub cidr_to_dotted_decimal {
    my ($prefix) = @_;
    return '' if !defined $prefix || $prefix !~ /^\d+$/ || $prefix < 0 || $prefix > 32;
    return cidr_to_netmask($prefix);
}

sub ipv4_prefixlen_from_netmask {
    my ($netmask) = @_;
    return '' if !is_valid_ipv4_literal($netmask);
    my $packed = eval {
        require Socket;
        Socket::inet_aton($netmask);
    };
    return '' if !$packed;

    my $mask = unpack('N', $packed);
    my $prefix = 0;
    my $seen_zero = 0;
    for (my $bit = 31; $bit >= 0; $bit--) {
        if (($mask >> $bit) & 1) {
            return '' if $seen_zero;    # non-contiguous mask
            $prefix++;
        } else {
            $seen_zero = 1;
        }
    }
    return $prefix;
}

sub is_disallowed_sfos_host_ip {
    my ($ip) = @_;
    return 1 if !defined $ip || $ip eq '';
    return 1 if $ip eq '0.0.0.0' || $ip eq '127.0.0.1' || $ip eq '::' || $ip eq '::1';
    return 0;
}

sub is_disallowed_smu_export_hostname {
    my ($hostname) = @_;
    return 0 if !defined $hostname;
    $hostname =~ s/^\s+|\s+$//g;
    return 0 if $hostname eq '';
    $hostname =~ s/\.+$//g;

    my $key = lc($hostname);
    return 1 if $key eq 'all.broker.sophos.com';
    return 0;
}

sub is_valid_sfos_fqdn {
    my ($fqdn) = @_;
    if (!defined $fqdn || $fqdn eq '') {
        debug_validation_failure('is_valid_sfos_fqdn', $fqdn, 'value is empty');
        return 0;
    }
    if (index($fqdn, '.') < 0) {
        debug_validation_failure('is_valid_sfos_fqdn', $fqdn, 'hostname must contain at least one dot for SFOS FQDNHost');
        return 0;
    }
    my @label_name = split /\./, $fqdn;
    if (!@label_name) {
        debug_validation_failure('is_valid_sfos_fqdn', $fqdn, 'no labels found');
        return 0;
    }
    if (length($label_name[0]) > 63) {
        debug_validation_failure('is_valid_sfos_fqdn', $fqdn, 'first label exceeds 63 characters');
        return 0;
    }
    if ($fqdn !~ /^((\*\.){0,1}[A-Za-z0-9_]+(-*[A-Za-z0-9_]+)*\.)+([A-Za-z0-9_]+(-*[A-Za-z0-9_]+)*)$/) {
        debug_validation_failure('is_valid_sfos_fqdn', $fqdn, 'does not match SFOS FQDN pattern');
        return 0;
    }
    return 1;
}

sub is_valid_sfos_hostname_label {
    my ($value) = @_;
    return 0 if !defined $value || $value eq '';
    return 1 if $value =~ /^[A-Za-z0-9_]+(?:-*[A-Za-z0-9_]+)*$/;
    return 0;
}

sub infer_local_domain_suffixes_for_fqdn {
    my ($backup) = @_;
    my @suffixes;
    my %seen;
    return \@suffixes if ref($backup) ne 'HASH';

    my $add_suffix = sub {
        my ($suffix) = @_;
        return if !defined $suffix;
        $suffix =~ s/^\s+|\s+$//g;
        $suffix =~ s/^\.+|\.+$//g;
        return if $suffix eq '';
        return if $suffix !~ /[A-Za-z0-9_]/;
        return if $suffix =~ /[^A-Za-z0-9_.-]/;
        return if $seen{lc($suffix)}++;
        push @suffixes, $suffix;
    };

    my $main = $backup->{main} // {};
    my $dns = $main->{dns};
    if (ref($dns) eq 'HASH') {
        for my $key (qw(domain domainname searchdomain search_domain localdomain suffix)) {
            $add_suffix->($dns->{$key}) if exists $dns->{$key};
        }
        if (exists $dns->{search}) {
            if (ref($dns->{search}) eq 'ARRAY') {
                for my $suffix (@{ $dns->{search} }) {
                    $add_suffix->($suffix);
                }
            } elsif (defined $dns->{search}) {
                for my $suffix (split /[\s,]+/, $dns->{search}) {
                    $add_suffix->($suffix);
                }
            }
        }
    }

    my $dhcp = $main->{dhcp};
    if (ref($dhcp) eq 'HASH') {
        for my $server (@{ ensure_arrayref($dhcp->{server}) }) {
            next if ref($server) ne 'HASH';
            for my $key (qw(domain domain_name domainname)) {
                $add_suffix->($server->{$key}) if exists $server->{$key};
            }
        }
    }

    return \@suffixes;
}

sub resolve_sfos_fqdn_value {
    my ($backup, $hostname) = @_;
    my %ret = (
        fqdn => '',
        transformed => 0,
        suffix => '',
        reason => '',
    );

    my $candidate = $hostname // '';
    $candidate =~ s/^\s+|\s+$//g;
    if ($candidate eq '') {
        $ret{reason} = 'hostname value is empty';
        return \%ret;
    }

    if (is_valid_sfos_fqdn($candidate)) {
        $ret{fqdn} = $candidate;
        return \%ret;
    }

    if (index($candidate, '.') < 0 && is_valid_sfos_hostname_label($candidate)) {
        my $suffixes = infer_local_domain_suffixes_for_fqdn($backup);
        for my $suffix (@$suffixes) {
            my $qualified = $candidate . '.' . $suffix;
            next if !is_valid_sfos_fqdn($qualified);
            $ret{fqdn} = $qualified;
            $ret{transformed} = 1;
            $ret{suffix} = $suffix;
            return \%ret;
        }
        $ret{reason} = 'single-label hostname is not SFOS-valid without a usable domain suffix';
        return \%ret;
    }

    $ret{reason} = 'hostname does not satisfy SFOS FQDN validation pattern';
    return \%ret;
}

sub is_valid_sfos_dns_host_entry_hostname {
    my ($hostname) = @_;
    return 0 if !defined $hostname;
    $hostname =~ s/^\s+|\s+$//g;
    return 0 if $hostname eq '';
    return 0 if length($hostname) > 253;
    return 0 if $hostname !~ /^[A-Za-z0-9_-]+(?:[.A-Za-z0-9-]+)*$/;
    return 1;
}

sub is_valid_sfos_dhcp_static_hostname {
    my ($hostname) = @_;
    return 0 if !defined $hostname;
    $hostname =~ s/^\s+|\s+$//g;
    return 0 if $hostname eq '';
    return 0 if $hostname =~ /^_/;
    return 0 if index($hostname, '._') != -1;
    return 1 if $hostname =~ /^\w(?:[_\.\-]?\w)*$/;
    return 1 if $hostname =~ /^\w(?:[_\.\-]?\w)*\.$/ && $hostname =~ /[A-Za-z]\.$/;
    return 0;
}

sub normalize_sfos_dhcp_static_hostname_candidate {
    my ($candidate) = @_;
    return '' if !defined $candidate;
    $candidate =~ s/^\s+|\s+$//g;
    return '' if $candidate eq '';
    $candidate =~ s/[^A-Za-z0-9_.-]+/-/g;
    $candidate =~ s/\._/-/g;
    $candidate =~ s/[_.-]{2,}/-/g;
    $candidate =~ s/^_+//g;
    $candidate =~ s/^[.-]+//g;
    $candidate =~ s/[_.-]+$//g;
    $candidate = trunc($candidate, 50);
    $candidate =~ s/[_.-]+$//g;
    return $candidate;
}

sub normalize_dhcp_static_hostname_for_sfos {
    my ($raw_hostname, $ip_address, $host_ref) = @_;
    my %ret = (
        hostname => '',
        changed => 0,
        source => 'original',
        reason => '',
        original_hostname => (defined $raw_hostname ? $raw_hostname : ''),
    );

    my $trimmed_original = $ret{original_hostname};
    $trimmed_original =~ s/^\s+|\s+$//g;
    if (is_valid_sfos_dhcp_static_hostname($trimmed_original)) {
        $ret{hostname} = $trimmed_original;
        return \%ret;
    }

    my @candidate_specs;
    my $normalized_original = normalize_sfos_dhcp_static_hostname_candidate($trimmed_original);
    push @candidate_specs, {
        value => $normalized_original,
        source => 'normalized-original',
        reason => 'normalized invalid hostname characters',
    } if $normalized_original ne '';

    if (defined $ip_address && $ip_address ne '') {
        my $seed_from_ip = normalize_sfos_dhcp_static_hostname_candidate('lease-' . $ip_address);
        push @candidate_specs, {
            value => $seed_from_ip,
            source => 'ip-fallback',
            reason => 'replaced invalid hostname with deterministic IP-based fallback',
        } if $seed_from_ip ne '';
    }

    if (defined $host_ref && $host_ref ne '') {
        my $seed_from_ref = normalize_sfos_dhcp_static_hostname_candidate($host_ref);
        push @candidate_specs, {
            value => $seed_from_ref,
            source => 'ref-fallback',
            reason => 'replaced invalid hostname with deterministic object-reference fallback',
        } if $seed_from_ref ne '';
    }

    my %seen_candidate;
    for my $spec (@candidate_specs) {
        my $candidate = $spec->{value} // '';
        next if $candidate eq '';
        my $dedup_key = lc($candidate);
        next if $seen_candidate{$dedup_key}++;
        next if !is_valid_sfos_dhcp_static_hostname($candidate);

        $ret{hostname} = $candidate;
        $ret{changed} = 1;
        $ret{source} = $spec->{source};
        $ret{reason} = $spec->{reason};
        return \%ret;
    }

    $ret{reason} = 'unable to derive SFOS-compatible DHCP static lease hostname';
    return \%ret;
}

sub build_dhcp_static_hostname_collision_suffix {
    my ($seed) = @_;
    return '' if !defined $seed;
    $seed =~ s/^\s+|\s+$//g;
    return '' if $seed eq '';
    $seed =~ s/[^A-Za-z0-9]+/-/g;
    $seed =~ s/-{2,}/-/g;
    $seed =~ s/^-+//g;
    $seed =~ s/-+$//g;
    return lc($seed);
}

sub project_unique_dhcp_static_hostname_for_sfos {
    my (%args) = @_;
    my $hostname = $args{hostname} // '';
    my $ip_address = $args{ip_address} // '';
    my $host_ref = $args{host_ref} // '';
    my $seen_hostnames = $args{seen_hostnames} // {};
    my $max_len = $args{max_len} // 50;

    my %ret = (
        hostname => '',
        changed => 0,
        collision => 0,
        source => '',
        reason => '',
    );
    return \%ret if $hostname eq '';

    my @candidate_specs = ({
        value => $hostname,
        source => 'normalized',
        collision => 0,
        reason => '',
    });
    my @collision_suffix_specs = ();
    my $ip_suffix = build_dhcp_static_hostname_collision_suffix($ip_address);
    if ($ip_suffix ne '') {
        push @collision_suffix_specs, {
            suffix => 'ip-' . $ip_suffix,
            source => 'ip-collision-suffix',
            reason => 'resolved hostname collision using deterministic IP-derived suffix',
        };
    }
    my $ref_suffix = build_dhcp_static_hostname_collision_suffix($host_ref);
    if ($ref_suffix ne '') {
        push @collision_suffix_specs, {
            suffix => 'ref-' . $ref_suffix,
            source => 'ref-collision-suffix',
            reason => 'resolved hostname collision using deterministic object-reference suffix',
        };
    }
    push @collision_suffix_specs, map {
        {
            suffix => 'dup' . $_,
            source => 'counter-collision-suffix',
            reason => 'resolved hostname collision using deterministic counter suffix',
        }
    } (2 .. 99);

    my %seen_candidate;
    for my $spec (@collision_suffix_specs) {
        my $suffix = $spec->{suffix} // '';
        next if $suffix eq '';
        my $base_len = $max_len - length($suffix) - 1;
        next if $base_len < 1;
        my $base = trunc($hostname, $base_len);
        $base =~ s/[_.-]+$//g;
        next if $base eq '';
        my $candidate = $base . '-' . $suffix;
        my $candidate_key = lc($candidate);
        next if $seen_candidate{$candidate_key}++;
        push @candidate_specs, {
            value => $candidate,
            source => $spec->{source},
            collision => 1,
            reason => $spec->{reason},
        };
    }

    for my $spec (@candidate_specs) {
        my $candidate = $spec->{value} // '';
        next if $candidate eq '';
        next if !is_valid_sfos_dhcp_static_hostname($candidate);
        my $dedup_key = lc($candidate);
        next if exists $seen_hostnames->{$dedup_key};
        $seen_hostnames->{$dedup_key} = 1;

        $ret{hostname} = $candidate;
        $ret{changed} = ($candidate ne $hostname) ? 1 : 0;
        $ret{collision} = $spec->{collision} ? 1 : 0;
        $ret{source} = $spec->{source} // '';
        $ret{reason} = $spec->{reason} // '';
        return \%ret;
    }

    $ret{reason} = 'unable to derive unique SFOS-compatible DHCP static lease hostname';
    return \%ret;
}

sub enforce_dhcp_static_lease_tuple_consistency {
    my (%args) = @_;
    my $server_name = $args{server_name} // '';
    my $leases = ensure_arrayref($args{leases});
    my @filtered = ();
    my %seen_hostname;

    for my $lease (@$leases) {
        next if ref($lease) ne 'HASH';
        my $hostname = $lease->{hostname} // '';
        my $mac_address = $lease->{mac_address} // '';
        my $ip_address = $lease->{ip_address} // '';
        if ($hostname eq '' || $mac_address eq '' || $ip_address eq '') {
            add_warning('dhcp-static', 'Skipping DHCP static lease because one or more tuple fields are missing after projection', {
                server => $server_name,
                hostname => $hostname,
                mac_address => $mac_address,
                ip_address => $ip_address,
            });
            increment_stat('dhcp.static.tuple.skipped.incomplete');
            next;
        }
        my $hostname_key = lc($hostname);
        if ($seen_hostname{$hostname_key}++) {
            add_warning('dhcp-static', 'Skipping DHCP static lease to preserve unique HostName cardinality for SFOS import', {
                server => $server_name,
                hostname => $hostname,
                mac_address => $mac_address,
                ip_address => $ip_address,
            });
            increment_stat('dhcp.static.hostname.duplicate.skipped');
            next;
        }
        push @filtered, $lease;
    }

    if (@filtered != @$leases) {
        add_warning('dhcp-static', 'Filtered DHCP static leases to keep HostName/MAC/IP tuple cardinality import-safe', {
            server => $server_name,
            before => scalar(@$leases),
            after => scalar(@filtered),
        });
        increment_stat('dhcp.static.tuple.filtered');
    }
    return \@filtered;
}

sub is_valid_sfos_dns_host_entry_ipv4 {
    my ($ip) = @_;
    return 0 if !is_valid_ipv4_literal($ip);
    return 0 if is_disallowed_sfos_host_ip($ip);
    my @octets = split /\./, $ip;
    return 0 if @octets != 4;
    return 0 if $octets[0] == 0;
    return 0 if $octets[0] == 169 && $octets[1] == 254;
    return 0 if $octets[0] >= 224;
    return 0 if $ip eq '255.255.255.255';
    return 1;
}

sub is_valid_sfos_dns_host_entry_ipv6 {
    my ($ip) = @_;
    return 0 if !is_valid_ipv6_literal($ip);
    return 0 if is_disallowed_sfos_host_ip($ip);
    return 0 if $ip =~ /^ff/i;
    return 0 if $ip =~ /^fe[89ab]/i;
    return 1;
}

sub is_valid_ipv4_literal {
    my ($ip) = @_;
    if (!defined $ip || $ip eq '') {
        debug_validation_failure('is_valid_ipv4_literal', $ip, 'value is empty');
        return 0;
    }
    if ($ip !~ /^\d{1,3}(?:\.\d{1,3}){3}$/) {
        debug_validation_failure('is_valid_ipv4_literal', $ip, 'does not match dotted-quad format');
        return 0;
    }
    my @parts = split /\./, $ip;
    if (scalar @parts != 4) {
        debug_validation_failure('is_valid_ipv4_literal', $ip, 'does not contain exactly 4 octets');
        return 0;
    }
    for my $idx (0..$#parts) {
        my $part = $parts[$idx];
        if ($part < 0 || $part > 255) {
            debug_validation_failure('is_valid_ipv4_literal', $ip, 'octet ' . ($idx + 1) . ' out of range 0..255');
            return 0;
        }
    }
    return 1;
}

sub is_valid_ipv6_literal {
    my ($ip) = @_;
    if (!defined $ip || $ip eq '') {
        debug_validation_failure('is_valid_ipv6_literal', $ip, 'value is empty');
        return 0;
    }
    return 0 if $ip eq '::';
    my $packed = eval {
        require Socket;
        Socket::inet_pton(Socket::AF_INET6(), $ip);
    };
    if (!$packed) {
        debug_validation_failure('is_valid_ipv6_literal', $ip, 'does not match IPv6 literal format');
        return 0;
    }
    return 1;
}

sub normalize_ipv4_or_empty {
    my ($ip) = @_;
    return '' if !defined $ip || $ip eq '' || $ip eq '0.0.0.0';
    return '' if !is_valid_ipv4_literal($ip);
    return $ip;
}

sub get_ref {
    my ($backup, $ref_name) = @_;
    return undef if !defined $ref_name || $ref_name eq '';
    return $backup->{objects}{$ref_name};
}

sub port_range {
    my ($low, $high) = @_;
    return $low eq $high ? $low : "$low:$high";
}

sub escape_html {
    my $html = shift;
    return "" if (!defined $html || $html eq "");
    $html =~ s/&/&amp;/g;
    $html =~ s/</&lt;/g;
    $html =~ s/>/&gt;/g;
    $html =~ s/"/&quot;/g;
    return $html;
}

sub trunc {
    my $s  = shift;
    my $len = shift || 50;
    return "" if (!defined $s || $s eq "");
    return substr($s, 0, $len);
}

sub escape_trunc {
    my $s = shift;
    my $len = shift || 50;
    return "" if (!defined $s || $s eq "");
    $s = trunc($s,$len);
    $s = escape_html($s);
    return $s;
}

sub sanitize_name {
    my ($name) = @_;
    $name =~ s/[^a-zA-Z0-9]+/_/g;
    return $name;
}

sub is_any_network {
    my ($network_obj) = @_;
    if ($network_obj->{data}->{resolved}) {
        if ($network_obj->{data}->{address} eq '0.0.0.0'
                and $network_obj->{data}->{netmask} == 0) {
            return 1;
        }
    }
    if ($network_obj->{data}->{resolved6}) {
        if ($network_obj->{data}->{address6} eq '::'
                and $network_obj->{data}->{netmask6} == 0) {
            return 1;
        }
    }
    return 0;
}

sub network_name {
    my ($backup, $network_obj) = @_;
    my $entries = project_network_object_entries($backup, $network_obj);
    return {} if !@$entries;
    my $name = ref_to_preferred_network_name($backup, $network_obj->{ref} // '');
    if ($name ne '') {
        return { name => $name };
    }
    return { name => $entries->[0]->{name} };
}

sub split_array {
    # destructive
    my ($n, $aref) = @_;
    my @ret;
    push @ret, [ splice @$aref, 0, $n ] while @$aref;
    return \@ret;
}

sub stable_smu_hash_suffix {
    my ($seed) = @_;
    $seed = '' if !defined $seed;
    $seed = 'smu-fqdn-default' if $seed eq '';
    return uc(substr(md5_hex($seed), 0, 8));
}

sub build_migrated_fqdn_host_name {
    my ($base_name, $seed) = @_;
    my $max_len = 50;
    my $suffix = 'SMU_' . stable_smu_hash_suffix($seed);
    my $base = $base_name // '';
    $base =~ s/\s+/ /g;
    $base =~ s/^\s+|\s+$//g;
    $base = 'FQDN Host' if $base eq '';

    my $budget = $max_len - length($suffix) - 1;
    $budget = 1 if $budget < 1;
    my $trimmed = trunc($base, $budget);
    return escape_html($trimmed . ' ' . $suffix);
}

sub parse_one_host_from_dns_host {
    my ($backup, $obj) = @_;
    my @ret = ();
    my $fqdn_result = resolve_sfos_fqdn_value($backup, $obj->{data}->{hostname});
    if ($fqdn_result->{fqdn} ne '') {
        if (is_disallowed_smu_export_hostname($fqdn_result->{fqdn})) {
            add_warning('host-fqdn', 'Skipping blacklisted FQDN host value from export', {
                object => $obj->{data}->{name} // $obj->{ref},
                hostname => $obj->{data}->{hostname} // '',
                fqdn => $fqdn_result->{fqdn},
            });
            increment_stat('host.fqdn.skipped.blacklisted');
        } else {
            push @ret, {
                fqdn => 1,
                name => build_migrated_fqdn_host_name(
                    "DNS Host: " . ($obj->{data}->{name} // ''),
                    join('|',
                        'dns_host_fqdn',
                        ($obj->{ref} // ''),
                        ($obj->{data}->{name} // ''),
                        ($fqdn_result->{fqdn} // '')
                    )
                ),
                type => 'FQDN',
                address => $fqdn_result->{fqdn}
            };
            if ($fqdn_result->{transformed}) {
                add_warning('host-fqdn', 'Normalized single-label hostname to SFOS-valid FQDN using inferred domain suffix', {
                    object => $obj->{data}->{name} // $obj->{ref},
                    hostname => $obj->{data}->{hostname} // '',
                    fqdn => $fqdn_result->{fqdn},
                    suffix => $fqdn_result->{suffix},
                });
            }
        }
    } else {
        add_warning('host-fqdn', 'Skipping invalid FQDN host value for SFOS validation compatibility', {
            object => $obj->{data}->{name} // $obj->{ref},
            hostname => $obj->{data}->{hostname} // '',
            reason => $fqdn_result->{reason} // '',
        });
    }

    if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && !is_disallowed_sfos_host_ip($obj->{data}->{address})) {
        # DNS Host is resolved; create an IP Host.
        push @ret, {
            iphost => 1,
            name => escape_trunc("DNS Host IP: ".$obj->{data}->{name}),
            type => 'IP',
            family => 'IPv4',
            address => $obj->{data}->{address}
        };
    }

    if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && !is_disallowed_sfos_host_ip($obj->{data}->{address6})) {
        push @ret, {
            iphost => 1,
            name => escape_trunc("DNS Host IPv6: ".$obj->{data}->{name}),
            type => 'IP',
            family => 'IPv6',
            address => $obj->{data}->{address6}
        };
    }
    return \@ret;
}

sub parse_one_host_from_host {
    my ($backup, $obj) = @_;
    my @ret = ();
    if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && !is_disallowed_sfos_host_ip($obj->{data}->{address})) {
        push @ret, {
            iphost => 1,
            name => escape_trunc("Host IP: ".$obj->{data}->{name}),
            type => 'IP',
            family => 'IPv4',
            address => $obj->{data}->{address}
        };
    }

    if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && !is_disallowed_sfos_host_ip($obj->{data}->{address6})) {
        push @ret, {
            iphost => 1,
            name => escape_trunc("Host IPv6: ".$obj->{data}->{name}),
            type => 'IP',
            family => 'IPv6',
            address => $obj->{data}->{address6}
        };
    }
    if ($obj->{data}->{hostnames}) {
        my @hostnames = @{ $obj->{data}->{hostnames} };
        my $i = 1;
        foreach my $hostname (@hostnames) {
            my $fqdn_result = resolve_sfos_fqdn_value($backup, $hostname);
            if ($fqdn_result->{fqdn} eq '') {
                add_warning('host-fqdn', 'Skipping invalid hostnames[] FQDN entry for SFOS validation compatibility', {
                    object => $obj->{data}->{name} // $obj->{ref},
                    hostname => $hostname // '',
                    reason => $fqdn_result->{reason} // '',
                });
                $i++;
                next;
            }
            if (is_disallowed_smu_export_hostname($fqdn_result->{fqdn})) {
                add_warning('host-fqdn', 'Skipping blacklisted hostnames[] FQDN entry from export', {
                    object => $obj->{data}->{name} // $obj->{ref},
                    hostname => $hostname // '',
                    fqdn => $fqdn_result->{fqdn},
                });
                increment_stat('host.fqdn.skipped.blacklisted');
                $i++;
                next;
            }
            push @ret, {
                fqdn => 1,
                name => build_migrated_fqdn_host_name(
                    "IP Host DNS: " . ($obj->{data}->{name} // '') . " $i",
                    join('|',
                        'hostnames_fqdn',
                        ($obj->{ref} // ''),
                        ($hostname // ''),
                        $i,
                        ($fqdn_result->{fqdn} // '')
                    )
                ),
                type => 'FQDN',
                address => $fqdn_result->{fqdn}
            };
            if ($fqdn_result->{transformed}) {
                add_warning('host-fqdn', 'Normalized single-label hostname to SFOS-valid FQDN using inferred domain suffix', {
                    object => $obj->{data}->{name} // $obj->{ref},
                    hostname => $hostname // '',
                    fqdn => $fqdn_result->{fqdn},
                    suffix => $fqdn_result->{suffix},
                });
            }
            $i++;
        }
    }
    my @macs;
    foreach my $mac (@{ $obj->{data}->{macs} }) {
        push @macs, {mac => $mac};
    }
    if (@macs) {
        push @ret, {
            maclist => 1,
            name => escape_trunc("IP Host MACs: ".$obj->{data}->{name}),
            type => 'MACList',
            macs => \@macs
        };
    }
    return \@ret;
}

sub parse_one_host_from_network {
    my ($backup, $obj) = @_;
    my @ret = ();
    if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && $obj->{data}->{address} ne "0.0.0.0") {
        push @ret, {
            network => 1,
            name => escape_trunc("Network: ".$obj->{data}->{name}),
            type => 'Network',
            family => 'IPv4',
            address => $obj->{data}->{address},
            subnet => $obj->{data}->{netmask} ? cidr_to_netmask($obj->{data}->{netmask}) : undef
        };
    }
    if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && $obj->{data}->{address6} ne "::") {
        push @ret, {
            network => 1,
            name => escape_trunc("Network IPv6: ".$obj->{data}->{name}),
            type => 'Network',
            family => 'IPv6',
            address => $obj->{data}->{address6},
            subnet => $obj->{data}->{netmask6}
        };
    }
    return \@ret;
}

sub parse_one_host_from_range {
    my ($backup, $obj) = @_;
    my @ret = ();
    if ($obj->{data}->{from} && $obj->{data}->{from} ne "") {
        push @ret, {
            range => 1,
            name => escape_trunc("Range: ".$obj->{data}->{name}),
            type => 'Range',
            family => 'IPv4',
            start_address => $obj->{data}->{from},
            end_address => $obj->{data}->{to}
        };
    }
    if ($obj->{data}->{from6} && $obj->{data}->{from6} ne "") {
        push @ret, {
            range => 1,
            name => escape_trunc("Range IPv6: ".$obj->{data}->{name}),
            type => 'Range',
            family => 'IPv6',
            start_address => $obj->{data}->{from6},
            end_address => $obj->{data}->{to6}
        };
    }
    return \@ret;
}

sub parse_one_host_from_availability_group {
    my ($backup, $obj) = @_;
    my @ret = ();

    if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && $obj->{data}->{address} ne "0.0.0.0" && !is_disallowed_sfos_host_ip($obj->{data}->{address})) {
        push @ret, {
            iphost => 1,
            name => escape_trunc("Host IP: ".$obj->{data}->{name}),
            type => 'IP',
            family => 'IPv4',
            address => $obj->{data}->{address},
        };
    }

    if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && $obj->{data}->{address6} ne "::" && !is_disallowed_sfos_host_ip($obj->{data}->{address6})) {
        push @ret, {
            iphost => 1,
            name => escape_trunc("Host IPv6: ".$obj->{data}->{name}),
            type => 'IP',
            family => 'IPv6',
            address => $obj->{data}->{address6},
        };
    }

    return \@ret;
}

sub parse_one_host_from_dns_group {
    my ($backup, $obj) = @_;
    my @ret = ();
    my $fqdn_result = resolve_sfos_fqdn_value($backup, $obj->{data}->{hostname});
    if ($fqdn_result->{fqdn} ne '') {
        if (is_disallowed_smu_export_hostname($fqdn_result->{fqdn})) {
            add_warning('host-fqdn', 'Skipping blacklisted FQDN host value from export', {
                object => $obj->{data}->{name} // $obj->{ref},
                hostname => $obj->{data}->{hostname} // '',
                fqdn => $fqdn_result->{fqdn},
            });
            increment_stat('host.fqdn.skipped.blacklisted');
        } else {
            push @ret, {
                fqdn => 1,
                name => build_migrated_fqdn_host_name(
                    "DNS Group FQDN: " . ($obj->{data}->{name} // ''),
                    join('|',
                        'dns_group_fqdn',
                        ($obj->{ref} // ''),
                        ($obj->{data}->{name} // ''),
                        ($fqdn_result->{fqdn} // '')
                    )
                ),
                type => 'FQDN',
                address => $fqdn_result->{fqdn}
            };
            if ($fqdn_result->{transformed}) {
                add_warning('host-fqdn', 'Normalized single-label DNS group hostname to SFOS-valid FQDN using inferred domain suffix', {
                    object => $obj->{data}->{name} // $obj->{ref},
                    hostname => $obj->{data}->{hostname} // '',
                    fqdn => $fqdn_result->{fqdn},
                    suffix => $fqdn_result->{suffix},
                });
            }
        }
    } else {
        add_warning('host-fqdn', 'Skipping invalid DNS group hostname for SFOS validation compatibility', {
            object => $obj->{data}->{name} // $obj->{ref},
            hostname => $obj->{data}->{hostname} // '',
            reason => $fqdn_result->{reason} // '',
        });
    }
    # DNSGrouptoIPLIST: Uncomment this section to enable export of resolved DNS Group IPs to an IPList in SFOS
    #my @addresses = @{ $obj->{data}->{addresses} };
    #if (@addresses) {
    #    push @ret, {
    #        name => escape_trunc("DNS Group: ".$obj->{data}->{hostname}),
    #        type => 'IPList',
    #        family => 'IPv4',
    #        addresses => join(',', @addresses)
    #    };
    #}
    #
    #my @addresses6 = @{ $obj->{data}->{addresses} };
    #if (@addresses6) {
    #    push @ret, {
    #        name => escape_trunc("DNS Group IPv6: ".$obj->{data}->{hostname}),
    #        type => 'IPList',
    #        family => 'IPv6',
    #        addresses => join(',', @addresses6)
    #    };
    #}
    return \@ret;
}

sub parse_one_host {
    my ($backup, $obj) = @_;
    my @ret = ();
    for ($obj->{type}) {
        if (defined $_ && $_ eq 'dns_host') {
            return parse_one_host_from_dns_host($backup, $obj);
        } elsif (defined $_ && ($_ eq 'host' or $_ eq 'interface_address' or $_ eq 'interface_broadcast')) {
            return parse_one_host_from_host($backup, $obj);
        } elsif (defined $_ && ($_ eq 'network' or $_ eq 'interface_network')) {
            return parse_one_host_from_network($backup, $obj);
        } elsif (defined $_ && $_ eq 'range') {
            return parse_one_host_from_range($backup, $obj);
        } elsif (defined $_ && $_ eq 'availability_group') {
            return parse_one_host_from_availability_group($backup, $obj);
        } elsif (defined $_ && $_ eq 'dns_group') {
            return parse_one_host_from_dns_group($backup, $obj);
        } elsif (defined $_ && $_ eq 'mac_list') {
            return parse_one_host_from_mac_list($backup, $obj);
        }
    }
    return \@ret;
}

sub parse_one_host_from_mac_list {
    my ($backup, $obj) = @_;
    my $data = $obj->{data};
    return [] if !defined $data;

    my @macs = @{ensure_arrayref($data->{address_list})};
    my @ret_macs;
    foreach my $mac (@macs) {
        push @ret_macs, { mac => $mac };
    }

    increment_stat('host.mac_list');
    return [{
        maclist => 1,
        name => escape_trunc($data->{name} // $obj->{ref}),
        macs => \@ret_macs,
    }];
}

sub parse_dns_host_entries {
    my ($backup) = @_;
    my @ret;
    my %seen_hostnames;
    my %seen_hostname_source;

    my $objects = $backup->{objects};
    return \@ret if ref($objects) ne 'HASH';

    for my $ref (sort keys %$objects) {
        my $obj = $objects->{$ref};
        next if !$obj || $obj->{class} ne 'network' || $obj->{type} ne 'host';

        my $data = $obj->{data};
        next if ref($data) ne 'HASH';

        my @hostnames = @{ ensure_arrayref($data->{hostnames}) };
        next if !@hostnames;

        my $object_name = $data->{name} // $ref;
        my @address_entries;

        my $address = $data->{address} // '';
        if ($address ne '') {
            if (is_valid_sfos_dns_host_entry_ipv4($address)) {
                push @address_entries, {
                    entry_type => 'Manual',
                    ip_family => 'IPv4',
                    ip_address => $address,
                    ttl => 3600,
                    weight => 1,
                    publish_on_wan => 'Disable',
                };
            } else {
                add_warning('dns-host-entry', 'Skipping IPv4 address for DNSHostEntry because it is not SFOS static-DNS valid', {
                    object => $object_name,
                    ip_address => $address,
                });
                increment_stat('dns.host_entry.skipped.invalid_ipv4');
            }
        }

        my $address6 = $data->{address6} // '';
        if ($address6 ne '') {
            if (is_valid_sfos_dns_host_entry_ipv6($address6)) {
                push @address_entries, {
                    entry_type => 'Manual',
                    ip_family => 'IPv6',
                    ip_address => $address6,
                    ttl => 3600,
                    weight => 1,
                    publish_on_wan => 'Disable',
                };
            } else {
                add_warning('dns-host-entry', 'Skipping IPv6 address for DNSHostEntry because it is not SFOS static-DNS valid', {
                    object => $object_name,
                    ip_address => $address6,
                });
                increment_stat('dns.host_entry.skipped.invalid_ipv6');
            }
        }

        if (!@address_entries) {
            add_warning('dns-host-entry', 'Skipping DNSHostEntry export because no SFOS-valid static address exists on host object', {
                object => $object_name,
            });
            increment_stat('dns.host_entry.skipped.no_address');
            next;
        }

        my $reverse_dns_requested = is_true($data->{reverse_dns});
        my $reverse_dns_assigned = 0;

        for (my $idx = 0; $idx <= $#hostnames; $idx++) {
            my $hostname = $hostnames[$idx] // '';
            $hostname =~ s/^\s+|\s+$//g;

            if (!is_valid_sfos_dns_host_entry_hostname($hostname)) {
                add_warning('dns-host-entry', 'Skipping static hostname because it is not SFOS DNSHostEntry compatible', {
                    object => $object_name,
                    hostname => $hostnames[$idx] // '',
                });
                increment_stat('dns.host_entry.skipped.invalid_hostname');
                next;
            }
            if (is_disallowed_smu_export_hostname($hostname)) {
                add_warning('dns-host-entry', 'Skipping blacklisted hostname from DNSHostEntry export', {
                    object => $object_name,
                    hostname => $hostnames[$idx] // '',
                });
                increment_stat('dns.host_entry.skipped.blacklisted_hostname');
                next;
            }

            my $hostname_key = lc($hostname);
            if (exists $seen_hostnames{$hostname_key}) {
                add_warning('dns-host-entry', 'Skipping duplicate static hostname; keeping first deterministic occurrence only', {
                    hostname => $hostname,
                    object => $object_name,
                    first_object => $seen_hostname_source{$hostname_key} // '',
                });
                increment_stat('dns.host_entry.skipped.duplicate_hostname');
                next;
            }
            $seen_hostnames{$hostname_key} = 1;
            $seen_hostname_source{$hostname_key} = $object_name;

            my $reverse_dns_lookup = ($reverse_dns_requested && $idx == 0) ? 'Enable' : 'Disable';
            $reverse_dns_assigned = 1 if $reverse_dns_lookup eq 'Enable';

            push @ret, {
                dnshostentry => 1,
                hostname => escape_html($hostname),
                addresses => [ map { +{ %$_ } } @address_entries ],
                reverse_dns_lookup => $reverse_dns_lookup,
            };
            increment_stat('dns.host_entry.emitted');
        }

        if ($reverse_dns_requested && !$reverse_dns_assigned) {
            add_warning('dns-host-entry', 'reverse_dns requested but no primary hostname could be exported for DNSHostEntry', {
                object => $object_name,
            });
            increment_stat('dns.host_entry.skipped.reverse_primary_missing');
        }
    }

    return \@ret;
}

sub is_sfos_gateway_interface_name {
    my ($name) = @_;
    return 0 if !defined $name || $name eq '';
    return 1 if $name =~ /^Port\d+(?:\.\d+)?$/i;
    return 0;
}

sub map_utm_interface_name_to_sfos {
    my ($name) = @_;
    return '' if !defined $name;
    $name =~ s/^\s+|\s+$//g;
    return '' if $name eq '' || $name eq '-1';

    if ($name =~ /^Port(\d+)(?:\.(\d+))?$/i) {
        return defined $2 ? "Port$1.$2" : "Port$1";
    }

    if ($name =~ /^eth(\d+)(?:\.(\d+))?$/i) {
        my $port = $1 + 1;
        return defined $2 ? "Port$port.$2" : "Port$port";
    }

    return '';
}

sub find_interface_object_for_primary_ref {
    my ($backup, $primary_ref) = @_;
    return undef if ref($backup) ne 'HASH' || !defined $primary_ref || $primary_ref eq '';

    for my $obj (values %{ $backup->{objects} // {} }) {
        next if !$obj || ($obj->{class} // '') ne 'interface';
        next if ref($obj->{data}) ne 'HASH';
        next if ($obj->{data}->{primary_address} // '') ne $primary_ref;
        return $obj;
    }

    return undef;
}

sub map_utm_interface_object_to_sfos {
    my (%args) = @_;
    my $backup = $args{backup};
    my $obj = $args{obj};
    my $ref = $args{ref} // '';
    return '' if ref($obj) ne 'HASH';

    my @candidates;
    my $data = ref($obj->{data}) eq 'HASH' ? $obj->{data} : {};
    push @candidates, $data->{name} // '';
    push @candidates, $data->{hardware} // '';

    if (($obj->{class} // '') eq 'interface') {
        my $itfhw_ref = $data->{itfhw} // '';
        if ($itfhw_ref ne '') {
            my $itfhw_obj = get_ref($backup, $itfhw_ref);
            if ($itfhw_obj && ref($itfhw_obj->{data}) eq 'HASH') {
                push @candidates, $itfhw_obj->{data}->{hardware} // '';
                push @candidates, $itfhw_obj->{data}->{name} // '';
            }
        }
    } elsif (($obj->{class} // '') eq 'itfparams' && ($obj->{type} // '') eq 'primary') {
        my $interface_obj = find_interface_object_for_primary_ref($backup, $ref);
        if ($interface_obj && ref($interface_obj->{data}) eq 'HASH') {
            push @candidates, $interface_obj->{data}->{name} // '';
            my $itfhw_ref = $interface_obj->{data}->{itfhw} // '';
            if ($itfhw_ref ne '') {
                my $itfhw_obj = get_ref($backup, $itfhw_ref);
                if ($itfhw_obj && ref($itfhw_obj->{data}) eq 'HASH') {
                    push @candidates, $itfhw_obj->{data}->{hardware} // '';
                    push @candidates, $itfhw_obj->{data}->{name} // '';
                }
            }
        }
    }

    my %seen;
    for my $candidate (@candidates) {
        next if !defined $candidate || $candidate eq '';
        next if $seen{$candidate}++;
        my $mapped = map_utm_interface_name_to_sfos($candidate);
        return $mapped if $mapped ne '';
    }

    return '';
}

sub is_valid_sfos_pim_rp_ip {
    my ($ip) = @_;
    return 0 if !is_valid_ipv4_literal($ip);
    return 0 if $ip eq '0.0.0.0' || $ip eq '255.255.255.255';
    my @octets = split /\./, $ip;
    return 0 if @octets != 4;
    return 0 if $octets[0] == 127;
    return 0 if $octets[0] == 169 && $octets[1] == 254;
    return 0 if $octets[0] >= 224;
    return 1;
}

sub pim_multicast_group_cidr_from_ref {
    my ($backup, $group_ref) = @_;
    return '' if !defined $group_ref || $group_ref eq '';
    my $group = get_ref($backup, $group_ref);
    return '' if !$group || ($group->{class} // '') ne 'network' || ($group->{type} // '') ne 'multicast';
    return '' if ref($group->{data}) ne 'HASH';

    my $address = $group->{data}->{address} // '';
    return '' if !is_valid_ipv4_literal($address);
    my @octets = split /\./, $address;
    return '' if @octets != 4;
    return '' if $octets[0] < 224 || $octets[0] > 239;
    return '' if $octets[0] == 224 && $octets[1] == 0 && $octets[2] == 0;

    my $netmask = $group->{data}->{netmask};
    $netmask = 32 if !defined $netmask || $netmask eq '';
    return '' if $netmask !~ /^\d+$/ || $netmask < 4 || $netmask > 32;

    return $address . '/' . $netmask;
}

sub collect_pim_interface_rows {
    my ($backup, $pim) = @_;
    my @interface_rows;
    my %seen_interface;
    my %unsupported_fields = (
        dr_priority => 0,
        igmp_versions => 0,
    );

    for my $pim_iface_ref (@{ ensure_arrayref($pim->{interfaces}) }) {
        next if !defined $pim_iface_ref || $pim_iface_ref eq '';
        my $pim_iface = get_ref($backup, $pim_iface_ref);
        if (
            !$pim_iface
            || ($pim_iface->{class} // '') ne 'pim_sm'
            || ($pim_iface->{type} // '') ne 'interface'
            || ref($pim_iface->{data}) ne 'HASH'
        ) {
            add_warning('pim-sm', 'Skipping unresolved or incompatible pim_sm/interface reference while building PIMDynamicRouting', {
                reference => $pim_iface_ref,
            });
            increment_stat('pim_sm.interface.skipped.unresolved');
            next;
        }

        my $iface_data = $pim_iface->{data};
        my $dr_priority = $iface_data->{dr_priority};
        $unsupported_fields{dr_priority}++ if defined $dr_priority && $dr_priority ne '' && $dr_priority != 0;

        my @igmp_versions = map { lc($_ // '') } @{ ensure_arrayref($iface_data->{igmp_versions}) };
        @igmp_versions = grep { $_ ne '' } @igmp_versions;
        my %expected = map { $_ => 1 } qw(v2 v3);
        my $igmp_is_default = @igmp_versions == 2 && $expected{$igmp_versions[0]} && $expected{$igmp_versions[1]};
        $unsupported_fields{igmp_versions}++ if @igmp_versions && !$igmp_is_default;

        my $interface_ref = $iface_data->{interface} // '';
        if ($interface_ref eq '') {
            add_warning('pim-sm', 'Skipping pim_sm/interface entry with missing interface reference', {
                reference => $pim_iface_ref,
            });
            increment_stat('pim_sm.interface.skipped.missing_interface_ref');
            next;
        }

        my $interface_obj = get_ref($backup, $interface_ref);
        my $utm_interface_name = ref_to_object_name($backup, $interface_ref);
        if ($utm_interface_name eq '') {
            add_warning('pim-sm', 'Skipping pim_sm/interface entry because referenced interface object could not be resolved', {
                reference => $pim_iface_ref,
                interface_ref => $interface_ref,
            });
            increment_stat('pim_sm.interface.skipped.interface_unresolved');
            next;
        }

        my $sfos_interface_name = map_utm_interface_object_to_sfos(
            backup => $backup,
            obj => $interface_obj,
            ref => $interface_ref,
        );
        if ($sfos_interface_name eq '') {
            my $fallback_interface = map_utm_interface_name_to_sfos($INTERFACE_ROUTE_NAME);
            if ($fallback_interface ne '') {
                add_warning('pim-sm', 'PIM interface is not directly SFOS-compatible after object-aware resolution; using interface default override (-I) for import safety', {
                    reference => $pim_iface_ref,
                    interface_ref => $interface_ref,
                    source_interface => $utm_interface_name,
                    fallback_interface => $fallback_interface,
                });
                $sfos_interface_name = $fallback_interface;
            }
        }
        if ($sfos_interface_name eq '') {
            add_warning('pim-sm', 'Skipping pim_sm/interface entry because source interface is not SFOS-compatible', {
                reference => $pim_iface_ref,
                interface_ref => $interface_ref,
                source_interface => $utm_interface_name,
            });
            increment_stat('pim_sm.interface.skipped.interface_unmapped');
            next;
        }

        next if $seen_interface{$sfos_interface_name}++;
        push @interface_rows, { name => $sfos_interface_name };
    }

    return \@interface_rows, \%unsupported_fields;
}

sub collect_pim_static_rp_rows {
    my ($backup, $pim) = @_;
    my @rp_order;
    my %rp_groups_by_ip;
    my %rp_group_seen;
    my %global_group_seen;

    for my $rp_ref (@{ ensure_arrayref($pim->{rp_routers}) }) {
        next if !defined $rp_ref || $rp_ref eq '';
        my $rp_obj = get_ref($backup, $rp_ref);
        if (
            !$rp_obj
            || ($rp_obj->{class} // '') ne 'pim_sm'
            || ($rp_obj->{type} // '') ne 'rp_router'
            || ref($rp_obj->{data}) ne 'HASH'
        ) {
            add_warning('pim-sm', 'Skipping unresolved or incompatible pim_sm/rp_router reference while building PIMDynamicRouting', {
                reference => $rp_ref,
            });
            increment_stat('pim_sm.rp.skipped.unresolved');
            next;
        }

        my $rp_data = $rp_obj->{data};
        my $host_ref = $rp_data->{host} // '';
        my $host_obj = get_ref($backup, $host_ref);
        my $rp_ip = ($host_obj && ref($host_obj->{data}) eq 'HASH') ? ($host_obj->{data}->{address} // '') : '';
        if (!is_valid_sfos_pim_rp_ip($rp_ip)) {
            add_warning('pim-sm', 'Skipping pim_sm/rp_router entry because RP host does not resolve to an SFOS-valid IPv4 unicast address', {
                reference => $rp_ref,
                host_ref => $host_ref,
                rp_ip => $rp_ip,
            });
            increment_stat('pim_sm.rp.skipped.invalid_rp_ip');
            next;
        }

        if (!exists $rp_groups_by_ip{$rp_ip}) {
            $rp_groups_by_ip{$rp_ip} = [];
            push @rp_order, $rp_ip;
        }

        for my $group_ref (@{ ensure_arrayref($rp_data->{multicast_groups}) }) {
            my $cidr = pim_multicast_group_cidr_from_ref($backup, $group_ref);
            if ($cidr eq '') {
                add_warning('pim-sm', 'Skipping pim_sm/rp_router multicast group because it is not representable as an SFOS PIM group CIDR', {
                    reference => $rp_ref,
                    rp_ip => $rp_ip,
                    group_ref => $group_ref,
                });
                increment_stat('pim_sm.group.skipped.invalid');
                next;
            }

            if ($global_group_seen{$cidr}++) {
                add_warning('pim-sm', 'Skipping duplicate multicast group CIDR across RP rows to satisfy SFOS PIM validation', {
                    cidr => $cidr,
                    rp_ip => $rp_ip,
                });
                increment_stat('pim_sm.group.skipped.duplicate');
                next;
            }

            next if $rp_group_seen{$rp_ip}{$cidr}++;
            push @{ $rp_groups_by_ip{$rp_ip} }, $cidr;
        }
    }

    my @rows;
    for my $rp_ip (@rp_order) {
        my @groups = @{ $rp_groups_by_ip{$rp_ip} // [] };
        if (!@groups) {
            add_warning('pim-sm', 'Skipping pim_sm/rp_router entry because no SFOS-valid multicast groups remain after normalization', {
                rp_ip => $rp_ip,
            });
            increment_stat('pim_sm.rp.skipped.empty_groups');
            next;
        }

        if (@groups > 8) {
            add_warning('pim-sm', 'Trimming multicast groups per RP to SFOS maximum (8) for PIM import validation', {
                rp_ip => $rp_ip,
                before => scalar(@groups),
                after => 8,
            });
            increment_stat('pim_sm.group.trimmed');
            @groups = @groups[0..7];
        }

        push @rows, {
            rp_ip => $rp_ip,
            group_rows => [ map { { group_ip => $_ } } @groups ],
        };
    }

    if (@rows > 8) {
        add_warning('pim-sm', 'Trimming static RP list to SFOS maximum (8) for PIM import validation', {
            before => scalar(@rows),
            after => 8,
        });
        increment_stat('pim_sm.rp.trimmed');
        @rows = @rows[0..7];
    }

    return \@rows;
}

sub collect_pim_nonrepresentable_fields {
    my (%args) = @_;
    my $pim = $args{pim};
    my $unsupported_interface_fields = $args{unsupported_interface_fields};
    my $route_count = $args{route_count} // 0;
    my @fields;

    push @fields, 'spt_switch_status' if exists $pim->{spt_switch_status};
    push @fields, 'spt_switch_bytes' if exists $pim->{spt_switch_bytes};
    push @fields, 'debug' if exists $pim->{debug} && is_true($pim->{debug});
    push @fields, 'enable_subnet_multicasting' if exists $pim->{enable_subnet_multicasting} && is_true($pim->{enable_subnet_multicasting});
    push @fields, 'auto_pfrule' if exists $pim->{auto_pfrule} && is_true($pim->{auto_pfrule});
    push @fields, 'auto_pf_out' if exists $pim->{auto_pf_out} && ($pim->{auto_pf_out} // '') ne '';

    if (ref($unsupported_interface_fields) eq 'HASH') {
        push @fields, 'dr_priority' if ($unsupported_interface_fields->{dr_priority} // 0) > 0;
        push @fields, 'igmp_versions' if ($unsupported_interface_fields->{igmp_versions} // 0) > 0;
    }

    push @fields, 'pim_sm/route' if $route_count > 0;
    my %seen;
    @fields = grep { !$seen{$_}++ } @fields;
    return \@fields;
}

sub count_pim_sm_route_objects {
    my ($backup) = @_;
    my $count = 0;
    for my $obj (values %{ $backup->{objects} // {} }) {
        next if !$obj;
        next if ($obj->{class} // '') ne 'pim_sm';
        next if ($obj->{type} // '') ne 'route';
        $count++;
    }
    return $count;
}

sub collect_pim_sm_export_context {
    my ($backup) = @_;
    return $backup->{_smu_pim_sm_export_context} if ref($backup->{_smu_pim_sm_export_context}) eq 'HASH';

    my $context = {
        emit_pim => 0,
        pim_template => {},
    };

    my $main = $backup->{main};
    if (ref($main) ne 'HASH' || ref($main->{pim_sm}) ne 'HASH' || !exists $main->{pim_sm}->{status}) {
        $backup->{_smu_pim_sm_export_context} = $context;
        return $context;
    }

    my $pim = $main->{pim_sm};
    my $source_enabled = is_true($pim->{status});
    my ($interface_rows, $unsupported_interface_fields) = collect_pim_interface_rows($backup, $pim);
    my $static_rp_rows = collect_pim_static_rp_rows($backup, $pim);
    my $route_count = count_pim_sm_route_objects($backup);

    my $nonrepresentable_fields = collect_pim_nonrepresentable_fields(
        pim => $pim,
        unsupported_interface_fields => $unsupported_interface_fields,
        route_count => $route_count,
    );
    if (@$nonrepresentable_fields) {
        add_warning('pim-sm', 'UTM PIM fields without direct SFOS 2105.1 mapping are skipped in this export phase', {
            fields => $nonrepresentable_fields,
            route_object_count => $route_count,
        });
        increment_stat('pim_sm.field.skipped');
    }

    my $effective_enabled = $source_enabled ? 1 : 0;
    if ($source_enabled && !@$interface_rows) {
        add_warning('pim-sm', 'UTM PIM is enabled but no SFOS-compatible interfaces remained; exporting ManagePIM=Disable for import safety', {
            source_interface_count => scalar(@{ ensure_arrayref($pim->{interfaces}) }),
        });
        increment_stat('pim_sm.disabled.no_interfaces');
        $effective_enabled = 0;
    }
    if ($source_enabled && !@$static_rp_rows) {
        add_warning('pim-sm', 'UTM PIM is enabled but no SFOS-compatible static RP rows remained; exporting ManagePIM=Disable for import safety', {
            source_rp_count => scalar(@{ ensure_arrayref($pim->{rp_routers}) }),
        });
        increment_stat('pim_sm.disabled.no_rp');
        $effective_enabled = 0;
    }

    my $is_static_rp = @$static_rp_rows ? 1 : 0;

    $context->{emit_pim} = 1;
    $context->{pim_template} = {
        enabled => 1,
        manage_pim => $effective_enabled ? 'Enable' : 'Disable',
        is_enabled => $effective_enabled ? 1 : 0,
        has_interface_list => (@$interface_rows ? 1 : 0),
        interface_rows => $interface_rows,
        candidate_rp => $is_static_rp ? 'Static' : 'Disable',
        is_static_rp => $is_static_rp,
        static_rp_rows => $static_rp_rows,
        is_dynamic_rp => 0,
    };
    increment_stat('pim_sm.entity');
    increment_stat('pim_sm.source.enabled') if $source_enabled;
    if ($effective_enabled) {
        increment_stat('pim_sm.enabled');
    } else {
        increment_stat('pim_sm.disabled');
    }

    $backup->{_smu_pim_sm_export_context} = $context;
    return $context;
}

sub parse_pim_dynamic_routing {
    my ($backup) = @_;
    my $context = collect_pim_sm_export_context($backup);
    return [] if !$context->{emit_pim};
    return $context->{pim_template};
}

sub policy_route_name_for_family {
    my ($base_name, $ipfamily, $candidate_count) = @_;
    my $name = $base_name // '';
    if ($ipfamily eq 'IPv6' && $candidate_count > 1) {
        return $name . ' IPv6';
    }
    return $name;
}

sub is_sfos_valid_gateway_candidate {
    my ($ipfamily, $gateway_ip) = @_;
    $ipfamily = $ipfamily // 'IPv4';
    return 0 if !defined $gateway_ip || $gateway_ip eq '';
    if ($ipfamily eq 'IPv6') {
        return is_valid_ipv6_literal($gateway_ip) ? 1 : 0;
    }
    return 0 if $gateway_ip eq '0.0.0.0';
    return is_valid_ipv4_literal($gateway_ip) ? 1 : 0;
}

sub has_sfos_valid_gateway_candidate {
    my ($candidates) = @_;
    for my $candidate (@{ ensure_arrayref($candidates) }) {
        next if ref($candidate) ne 'HASH';
        my $ipfamily = $candidate->{ipfamily} // 'IPv4';
        my $gateway_ip = $candidate->{gateway_ip} // '';
        return 1 if is_sfos_valid_gateway_candidate($ipfamily, $gateway_ip);
    }
    return 0;
}

sub build_gateway_candidates {
    my (%args) = @_;
    my $gateway_ip = $args{gateway_ip} // '';
    my $gateway_ip6 = $args{gateway_ip6} // '';
    my @gateway_candidates;
    push @gateway_candidates, { ipfamily => 'IPv4', gateway_ip => $gateway_ip } if $gateway_ip ne '';
    push @gateway_candidates, { ipfamily => 'IPv6', gateway_ip => $gateway_ip6 } if $gateway_ip6 ne '';
    return \@gateway_candidates;
}

sub derive_fallback_policy_route_primary_gateway_context {
    my (%args) = @_;
    my $backup = $args{backup};
    my $exclude_primary_ref = $args{exclude_primary_ref} // '';
    return undef if ref($backup) ne 'HASH';

    for my $ref (sort keys %{ $backup->{objects} // {} }) {
        next if $exclude_primary_ref ne '' && $ref eq $exclude_primary_ref;
        my $obj = $backup->{objects}{$ref};
        next if !$obj;
        next if ($obj->{class} // '') ne 'itfparams' || ($obj->{type} // '') ne 'primary';
        next if !$obj->{data};

        my $gateway_candidates = build_gateway_candidates(
            gateway_ip => $obj->{data}->{default_gateway_address},
            gateway_ip6 => $obj->{data}->{default_gateway_address6},
        );
        next if !has_sfos_valid_gateway_candidate($gateway_candidates);

        return {
            primary_ref => $ref,
            primary_name => $obj->{data}->{name} // '',
            gateway_candidates => $gateway_candidates,
        };
    }
    return undef;
}

sub derive_route_policy_gateway_context {
    my ($backup, $obj) = @_;
    my $route_type = $obj->{data}->{type} // '';
    my $target_ref = $obj->{data}->{target} // '';
    my $target = get_ref($backup, $target_ref);
    my $target_name = ($target && $target->{data}) ? ($target->{data}->{name} // '') : '';

    my $interface = '';
    my $interface_state = 'none';
    my $primary_missing = 0;
    my $primary_name = '';
    my $primary_ref = '';
    my $fallback_gateway_used = 0;
    my $fallback_primary_ref = '';
    my $fallback_primary_name = '';
    my @gateway_candidates;

    if ($route_type eq 'itf') {
        my $mapped_interface = map_utm_interface_object_to_sfos(
            backup => $backup,
            obj => $target,
            ref => $target_ref,
        );
        if ($mapped_interface ne '') {
            $interface = $mapped_interface;
            $interface_state = (lc($target_name) ne lc($mapped_interface)) ? 'mapped' : 'exact';
        } elsif ($target_name ne '') {
            my $fallback_interface = map_utm_interface_name_to_sfos($INTERFACE_ROUTE_NAME);
            if ($fallback_interface ne '') {
                $interface = $fallback_interface;
                $interface_state = 'defaulted';
            } else {
                $interface_state = 'unmapped';
            }
        }

        $primary_ref = ($target && $target->{data}) ? ($target->{data}->{primary_address} // '') : '';
        my $primary = $primary_ref ne '' ? get_ref($backup, $primary_ref) : undef;
        if ($primary && $primary->{data}) {
            $primary_name = $primary->{data}->{name} // '';
            @gateway_candidates = @{ build_gateway_candidates(
                gateway_ip => $primary->{data}->{default_gateway_address},
                gateway_ip6 => $primary->{data}->{default_gateway_address6},
            ) };
        } else {
            $primary_missing = 1;
        }

        if (!has_sfos_valid_gateway_candidate(\@gateway_candidates)) {
            my $fallback_context = derive_fallback_policy_route_primary_gateway_context(
                backup => $backup,
                exclude_primary_ref => $primary_ref,
            );
            if ($fallback_context) {
                @gateway_candidates = @{ $fallback_context->{gateway_candidates} // [] };
                $primary_name = $fallback_context->{primary_name} // $primary_name;
                $primary_missing = 0;
                $fallback_gateway_used = 1;
                $fallback_primary_ref = $fallback_context->{primary_ref} // '';
                $fallback_primary_name = $fallback_context->{primary_name} // '';
            }
        }
    } else {
        @gateway_candidates = @{ build_gateway_candidates(
            gateway_ip => ($target && $target->{data}) ? ($target->{data}->{address} // '') : '',
            gateway_ip6 => ($target && $target->{data}) ? ($target->{data}->{address6} // '') : '',
        ) };
    }

    return {
        route_type => $route_type,
        target_ref => $target_ref,
        target_name => $target_name,
        interface => $interface,
        interface_state => $interface_state,
        primary_missing => $primary_missing,
        primary_name => $primary_name,
        primary_ref => $primary_ref,
        fallback_gateway_used => $fallback_gateway_used,
        fallback_primary_ref => $fallback_primary_ref,
        fallback_primary_name => $fallback_primary_name,
        gateway_candidates => \@gateway_candidates,
    };
}

sub validate_gateway_candidates_for_sfos {
    my (%args) = @_;
    my $name = $args{name} // '';
    my $warning_category = $args{warning_category} // 'gateway-host';
    my $invalid_message = $args{invalid_message} // 'Skipping gateway candidate with invalid GatewayIP for SFOS import';
    my @candidates = @{ ensure_arrayref($args{candidates}) };
    my @valid_candidates;

    for my $candidate (@candidates) {
        next if ref($candidate) ne 'HASH';
        my $gateway_ip = $candidate->{gateway_ip} // '';
        my $ipfamily = $candidate->{ipfamily} // 'IPv4';
        my $is_valid = is_sfos_valid_gateway_candidate($ipfamily, $gateway_ip);
        if (!$is_valid) {
            add_warning($warning_category, $invalid_message, {
                name => $name,
                gateway_ip => $gateway_ip,
                ipfamily => $ipfamily,
            });
            next;
        }
        push @valid_candidates, {
            ipfamily => $ipfamily,
            gateway_ip => $gateway_ip,
        };
    }

    return \@valid_candidates;
}

sub is_ipv4_firewall_network_name {
    my ($name) = @_;
    return 0 if !defined $name || $name eq '';
    return 1 if $name eq 'Any' || $name eq 'Any IPv4';
    return 1 if $name =~ /^(?:Host IP:|Network:|Range:)/;
    return 0;
}

sub filter_policy_route_network_rows_by_family {
    my (%args) = @_;
    my $rows = ensure_arrayref($args{rows});
    my $ipfamily = $args{ipfamily} // 'IPv4';
    my $route_name = $args{route_name} // '';

    my @filtered;
    my @dropped;
    my $any_match = 0;
    for my $row (@$rows) {
        next if ref($row) ne 'HASH';
        my $name = $row->{name} // '';
        next if $name eq '';

        if ($name eq 'Any') {
            $any_match = 1;
            next;
        }

        if ($ipfamily eq 'IPv4' && $name eq 'Any IPv4') {
            $any_match = 1;
            next;
        }
        if ($ipfamily eq 'IPv6' && $name eq 'Any IPv6') {
            $any_match = 1;
            next;
        }

        if ($ipfamily eq 'IPv4' && is_ipv6_firewall_network_name($name)) {
            push @dropped, $name;
            next;
        }
        if ($ipfamily eq 'IPv6' && is_ipv4_firewall_network_name($name)) {
            push @dropped, $name;
            next;
        }
        push @filtered, { name => $name };
    }

    if (@dropped) {
        my %seen_dropped;
        @dropped = grep { !$seen_dropped{$_}++ } @dropped;
        add_warning('sdwan-policy-route', 'Dropped family-mismatched source/destination references for SD-WAN policy route', {
            route => $route_name,
            ipfamily => $ipfamily,
            dropped_networks => \@dropped,
        });
        increment_stat('sdwan.policy_route.network_family_dropped', scalar @dropped);
    }

    return [] if $any_match;
    my %seen;
    @filtered = grep { !$seen{$_->{name}}++ } @filtered;
    return \@filtered;
}

sub collect_ordered_route_policy_objects {
    my ($backup) = @_;
    my @ordered;
    my %seen_refs;

    my @main_refs = @{ ensure_arrayref($backup->{main}->{routes}->{policy}) };
    for my $ref (@main_refs) {
        next if !defined $ref || $ref eq '' || $seen_refs{$ref}++;
        my $obj = get_ref($backup, $ref);
        next if !$obj;
        next if ($obj->{class} // '') ne 'route' || ($obj->{type} // '') ne 'policy';
        push @ordered, $obj;
    }

    for my $ref (sort keys %{ $backup->{objects} // {} }) {
        next if $seen_refs{$ref}++;
        my $obj = $backup->{objects}{$ref};
        next if !$obj;
        next if ($obj->{class} // '') ne 'route' || ($obj->{type} // '') ne 'policy';
        push @ordered, $obj;
    }

    return \@ordered;
}

sub resolve_policy_route_match_interface {
    my ($backup, $obj) = @_;
    my $interface_ref = $obj->{data}->{interface} // '';
    my %ret = (
        interface => '',
        source_interface => '',
        interface_ref => $interface_ref,
        state => 'none',
    );
    return \%ret if $interface_ref eq '' || $interface_ref eq '-1';

    my $source_interface = ref_to_object_name($backup, $interface_ref);
    $ret{source_interface} = $source_interface;
    if ($source_interface eq '') {
        $ret{state} = 'missing';
        return \%ret;
    }

    my $interface_obj = get_ref($backup, $interface_ref);
    my $mapped_interface = map_utm_interface_object_to_sfos(
        backup => $backup,
        obj => $interface_obj,
        ref => $interface_ref,
    );
    if ($mapped_interface ne '') {
        $ret{interface} = $mapped_interface;
        $ret{state} = (lc($source_interface) ne lc($mapped_interface)) ? 'mapped' : 'exact';
        return \%ret;
    }

    my $fallback_interface = map_utm_interface_name_to_sfos($INTERFACE_ROUTE_NAME);
    if ($fallback_interface ne '') {
        $ret{interface} = $fallback_interface;
        $ret{state} = 'defaulted';
        return \%ret;
    }

    $ret{state} = 'unmapped';
    return \%ret;
}

sub parse_one_gatewayhost {
    my ($backup, $obj) = @_;
    my $class_type = $obj->{class} . '/' . $obj->{type};
    my $name = $obj->{data}->{name} // $obj->{ref} // '';
    my $interface = '';
    my $healthcheck_enabled = 0;
    my @gateway_candidates;

    if ($class_type eq 'itfparams/primary') {
        my $source_interface = $obj->{data}->{name} // '';
        my $mapped_interface = map_utm_interface_object_to_sfos(
            backup => $backup,
            obj => $obj,
            ref => $obj->{ref} // '',
        );
        if ($mapped_interface ne '') {
            if (lc($source_interface) eq lc($mapped_interface)) {
                $interface = $mapped_interface;
            } else {
                add_warning('gateway-host', 'Mapped gateway interface to SFOS-compatible placeholder', {
                    name => $name,
                    source_interface => $source_interface,
                    mapped_interface => $mapped_interface,
                    gateway_ip => $obj->{data}->{default_gateway_address} // '',
                });
                increment_stat('gateway.host.interface.mapped');
            }
        } elsif ($source_interface ne '') {
            my $fallback_interface = map_utm_interface_name_to_sfos($INTERFACE_ROUTE_NAME);
            if ($fallback_interface ne '') {
                add_warning('gateway-host', 'Gateway interface name is not SFOS-compatible; using interface default override (-I)', {
                    name => $name,
                    source_interface => $source_interface,
                    fallback_interface => $fallback_interface,
                    gateway_ip => $obj->{data}->{default_gateway_address} // '',
                });
                increment_stat('gateway.host.interface.defaulted');
            } else {
                add_warning('gateway-host', 'Gateway interface name is not SFOS-compatible; exporting without explicit Interface binding', {
                    name => $name,
                    source_interface => $source_interface,
                    gateway_ip => $obj->{data}->{default_gateway_address} // '',
                });
                increment_stat('gateway.host.interface.unmapped');
            }
        }
        @gateway_candidates = @{ build_gateway_candidates(
            gateway_ip => $obj->{data}->{default_gateway_address},
            gateway_ip6 => $obj->{data}->{default_gateway_address6},
        ) };
        $healthcheck_enabled = 1;
    } elsif ($class_type eq 'route/policy') {
        my $gateway_context = derive_route_policy_gateway_context($backup, $obj);
        $interface = $gateway_context->{interface_state} && ($gateway_context->{interface_state} // '') eq 'exact'
            ? ($gateway_context->{interface} // '')
            : '';
        @gateway_candidates = @{ $gateway_context->{gateway_candidates} // [] };
        my $is_itf_route = (($gateway_context->{route_type} // '') eq 'itf');
        if ($is_itf_route) {
            my $interface_state = $gateway_context->{interface_state} // '';
            if ($interface_state eq 'mapped') {
                add_warning('gateway-host', 'Mapped policy-route interface to SFOS-compatible placeholder', {
                    name => $name,
                    target_interface => $gateway_context->{target_name} // '',
                    mapped_interface => $interface,
                    target => $gateway_context->{target_ref} // '',
                });
                increment_stat('gateway.host.policy.interface.mapped');
            } elsif ($interface_state eq 'defaulted') {
                add_warning('gateway-host', 'Policy-route target interface name is not SFOS-compatible; using interface default override (-I)', {
                    name => $name,
                    target_interface => $gateway_context->{target_name} // '',
                    fallback_interface => $interface,
                    target => $gateway_context->{target_ref} // '',
                });
                increment_stat('gateway.host.policy.interface.defaulted');
            } elsif ($interface_state eq 'unmapped') {
                add_warning('gateway-host', 'Policy-route target interface name is not SFOS-compatible; exporting without explicit Interface binding', {
                    name => $name,
                    target_interface => $gateway_context->{target_name} // '',
                    target => $gateway_context->{target_ref} // '',
                });
                increment_stat('gateway.host.policy.interface.unmapped');
            }

            if ($gateway_context->{fallback_gateway_used}) {
                add_warning('gateway-host', 'Policy-route target primary gateway was not SFOS-valid; using fallback primary gateway defaults', {
                    name => $name,
                    target_interface => $gateway_context->{target_name} // '',
                    target => $gateway_context->{target_ref} // '',
                    fallback_primary => $gateway_context->{fallback_primary_name} // '',
                    fallback_primary_ref => $gateway_context->{fallback_primary_ref} // '',
                });
                increment_stat('gateway.host.policy.gateway.defaulted');
            }

            if ($gateway_context->{primary_missing}) {
                add_warning('gateway-host', 'Policy-route interface target did not resolve to a primary interface address object; skipping gateway host export', {
                    name => $name,
                    target => $gateway_context->{target_ref} // '',
                });
            }
        } else {
            my $first_candidate = $gateway_candidates[0] // {};
            add_warning('gateway-host', 'Route-policy gateway host lacks deterministic SFOS interface mapping; keeping Healthcheck OFF', {
                name => $name,
                gateway_ip => $first_candidate->{gateway_ip} // '',
                target => $gateway_context->{target_ref} // '',
            });
        }
    } else {
        return [];
    }

    my @valid_gateway_candidates = @{ validate_gateway_candidates_for_sfos(
        name => $name,
        warning_category => 'gateway-host',
        invalid_message => 'Skipping gateway host candidate with invalid GatewayIP for SFOS import',
        candidates => \@gateway_candidates,
    ) };
    return [] if !@valid_gateway_candidates;

    my @records;
    my %seen;
    my $valid_gateway_candidate_count = scalar(@valid_gateway_candidates);
    for my $candidate (@valid_gateway_candidates) {
        my $ipfamily = $candidate->{ipfamily};
        my $gateway_ip = $candidate->{gateway_ip};
        next if $seen{$ipfamily . "\x1e" . $gateway_ip}++;

        my @monitor_rules = ();
        if ($healthcheck_enabled) {
            push @monitor_rules, {
                protocol => 'PING',
                host => $gateway_ip,
                port => '*',
                operator => '',
            };
        }

        my $gateway_name = escape_trunc(policy_route_name_for_family($name, $ipfamily, $valid_gateway_candidate_count));

        push @records, {
            name => $gateway_name,
            ipfamily => $ipfamily,
            gateway_ip => $gateway_ip,
            interface => $interface,
            has_interface => ($interface ne '' ? 1 : 0),
            healthcheck => ($healthcheck_enabled ? 'ON' : 'OFF'),
            healthcheck_enabled => ($healthcheck_enabled ? 1 : 0),
            monitor_rules => \@monitor_rules,
        };
    }

    return [] if !@records;
    return $records[0] if @records == 1;
    return \@records;
}

sub parse_sdwan_policy_routes {
    my ($backup) = @_;
    my @route_objects = @{ collect_ordered_route_policy_objects($backup) };
    my @rows;
    my %seen_route_gateway;

    for my $obj (@route_objects) {
        next if !$obj || ref($obj) ne 'HASH';
        my $name = $obj->{data}->{name} // $obj->{ref} // '';
        next if $name eq '';

        my $gateway_context = derive_route_policy_gateway_context($backup, $obj);
        my $route_type = $gateway_context->{route_type} // '';
        my $is_itf_route = ($route_type eq 'itf');
        if ($route_type ne 'itf' && $route_type ne 'host') {
            add_warning('sdwan-policy-route', 'Skipping route/policy object with unsupported route type for SD-WAN policy export', {
                name => $name,
                route_type => $route_type,
                ref => $obj->{ref} // '',
            });
            increment_stat('sdwan.policy_route.skipped.unsupported_type');
            next;
        }

        if ($is_itf_route && ($gateway_context->{primary_missing} // 0)) {
            add_warning('sdwan-policy-route', 'Skipping SD-WAN policy route because interface target did not resolve to primary gateway defaults', {
                name => $name,
                target => $gateway_context->{target_ref} // '',
            });
            increment_stat('sdwan.policy_route.skipped.primary_missing');
            next;
        }

        if ($is_itf_route && ($gateway_context->{fallback_gateway_used} // 0)) {
            add_warning('sdwan-policy-route', 'Policy-route target primary gateway was not SFOS-valid; using fallback primary gateway defaults', {
                name => $name,
                target_interface => $gateway_context->{target_name} // '',
                target => $gateway_context->{target_ref} // '',
                fallback_primary => $gateway_context->{fallback_primary_name} // '',
                fallback_primary_ref => $gateway_context->{fallback_primary_ref} // '',
            });
            increment_stat('sdwan.policy_route.gateway.defaulted');
        }

        my @valid_gateway_candidates = @{ validate_gateway_candidates_for_sfos(
            name => $name,
            warning_category => 'sdwan-policy-route',
            invalid_message => 'Skipping SD-WAN policy-route gateway candidate with invalid GatewayIP for SFOS import',
            candidates => $gateway_context->{gateway_candidates},
        ) };
        next if !@valid_gateway_candidates;

        my @source_rows = map { { name => $_ } } @{ ref_to_network_names($backup, $obj->{data}->{source}) };
        my @destination_rows = map { { name => $_ } } @{ ref_to_network_names($backup, $obj->{data}->{destination}) };
        my $service_name = ref_to_service_name($backup, $obj->{data}->{service});
        my @service_rows = $service_name ne '' ? ({ name => $service_name }) : ();

        my $match_interface = resolve_policy_route_match_interface($backup, $obj);
        my $match_interface_state = $match_interface->{state} // '';
        if ($match_interface_state eq 'mapped') {
            add_warning('sdwan-policy-route', 'Mapped policy-route selector interface to SFOS-compatible placeholder', {
                name => $name,
                source_interface => $match_interface->{source_interface} // '',
                mapped_interface => $match_interface->{interface} // '',
                interface_ref => $match_interface->{interface_ref} // '',
            });
            increment_stat('sdwan.policy_route.interface.mapped');
        } elsif ($match_interface_state eq 'defaulted') {
            add_warning('sdwan-policy-route', 'Policy-route selector interface name is not SFOS-compatible; using interface default override (-I)', {
                name => $name,
                source_interface => $match_interface->{source_interface} // '',
                fallback_interface => $match_interface->{interface} // '',
                interface_ref => $match_interface->{interface_ref} // '',
            });
            increment_stat('sdwan.policy_route.interface.defaulted');
        } elsif ($match_interface_state eq 'unmapped') {
            add_warning('sdwan-policy-route', 'Dropped policy-route selector interface because name is not SFOS-compatible', {
                name => $name,
                source_interface => $match_interface->{source_interface} // '',
                interface_ref => $match_interface->{interface_ref} // '',
            });
            increment_stat('sdwan.policy_route.interface.unmapped');
        } elsif ($match_interface_state eq 'missing') {
            add_warning('sdwan-policy-route', 'Dropped policy-route selector interface because interface reference did not resolve', {
                name => $name,
                interface_ref => $match_interface->{interface_ref} // '',
            });
            increment_stat('sdwan.policy_route.interface.missing');
        }

        my $gateway_base_name = $name;
        if ($is_itf_route && ($gateway_context->{primary_name} // '') ne '') {
            $gateway_base_name = $gateway_context->{primary_name};
        }

        my %seen_candidate;
        my $valid_gateway_candidate_count = scalar(@valid_gateway_candidates);
        my $selector_interface = $match_interface->{interface} // '';
        for my $candidate (@valid_gateway_candidates) {
            my $ipfamily = $candidate->{ipfamily} // 'IPv4';
            my $gateway_ip = $candidate->{gateway_ip} // '';
            next if $seen_candidate{$ipfamily . "\x1e" . $gateway_ip}++;

            my $route_name = policy_route_name_for_family($name, $ipfamily, $valid_gateway_candidate_count);
            my $gateway_name = policy_route_name_for_family($gateway_base_name, $ipfamily, $valid_gateway_candidate_count);
            next if $seen_route_gateway{$route_name . "\x1e" . $gateway_name}++;

            my $sources = filter_policy_route_network_rows_by_family(
                rows => \@source_rows,
                ipfamily => $ipfamily,
                route_name => $route_name,
            );
            my $destinations = filter_policy_route_network_rows_by_family(
                rows => \@destination_rows,
                ipfamily => $ipfamily,
                route_name => $route_name,
            );

            if ($selector_interface eq '' && !@$sources && !@$destinations && !@service_rows) {
                add_warning('sdwan-policy-route', 'Skipping SD-WAN policy route because no SFOS-valid match criteria remain after normalization', {
                    name => $route_name,
                    ipfamily => $ipfamily,
                });
                increment_stat('sdwan.policy_route.skipped.empty_selector');
                next;
            }

            push @rows, {
                name => escape_trunc($route_name),
                description => escape_html($obj->{data}->{comment} // ''),
                ipfamily => $ipfamily,
                interface => $selector_interface,
                has_interface => ($selector_interface ne '' ? 1 : 0),
                dscp_marking => '0-Best Effort',
                gateway => escape_trunc($gateway_name),
                link_selection => 'SelectGateways',
                healthcheck => 'OFF',
                status => ($obj->{data}->{status} ? '1' : '0'),
                sources => $sources,
                destinations => $destinations,
                services => \@service_rows,
            };
            increment_stat('sdwan.policy_route.emitted');
        }
    }

    return \@rows;
}

sub parse_one_service {
    my ($backup, $obj) = @_;
    my $data = $obj->{data};
    my $type = $obj->{type};

    my %SERVICE_TYPE_MAP = ( tcp => 'TCPorUDP', udp => 'TCPorUDP', tcpudp => 'TCPorUDP', ip => 'IP', icmp => 'ICMP', icmpv6 => 'ICMPv6', esp => 'IP', ah => 'IP' );

    # SFOS supports Services Type: TCPorUDP, IP, ICMP, ICMPv6.
    # For UTM service/tcpudp, emit a single TCPorUDP service with two ServiceDetail entries (TCP + UDP).

    # If it is service/any, we don't output an entity
    return [] if $type eq 'any';

    my %service = (
        name => escape_trunc($data->{name}),
        type => $SERVICE_TYPE_MAP{$type},
    );

    for ($type) {
        if ($_ eq 'tcp') {
            $service{tcpudp} = 1;
            $service{details} = [
                {
                    port_src => port_range( $data->{src_low}, $data->{src_high} ),
                    port_dst => port_range( $data->{dst_low}, $data->{dst_high} ),
                    protocol => 'TCP'
                }
            ];
        }
        elsif ($_ eq 'udp') {
            $service{tcpudp} = 1;
            $service{details} = [
                {
                    port_src => port_range( $data->{src_low}, $data->{src_high} ),
                    port_dst => port_range( $data->{dst_low}, $data->{dst_high} ),
                    protocol => 'UDP'
                }
            ];
        }
        elsif ($_ eq 'tcpudp') {
            $service{tcpudp} = 1;
            $service{details} = [
                {
                    port_src => port_range( $data->{src_low}, $data->{src_high} ),
                    port_dst => port_range( $data->{dst_low}, $data->{dst_high} ),
                    protocol => 'TCP'
                },
                {
                    port_src => port_range( $data->{src_low}, $data->{src_high} ),
                    port_dst => port_range( $data->{dst_low}, $data->{dst_high} ),
                    protocol => 'UDP'
                }
            ];
        }
        elsif ($_ eq 'ip') {
            $service{ip} = 1;
            $service{protocol_name} = $IP_PROTOS->{ $data->{proto} };
        }
        elsif ($_ eq 'esp') {
            $service{ip} = 1;
            $service{protocol_name} = 'ESP';
        }
        elsif ($_ eq 'ah') {
            $service{ip} = 1;
            $service{protocol_name} = 'AH';
        }
        elsif ($_ eq 'icmp') {
            $service{icmp} = 1;
            $service{icmp_type} = $ICMP4->{ $data->{type} }->{name};
            $service{icmp_code} = $ICMP4->{ $data->{type} }->{ $data->{code} } || 'Any code';
        }
        elsif ($_ eq 'icmpv6') {
            $service{icmpv6} = 1;
            $service{icmp_type} = $ICMP6->{ $data->{type} }->{name};
            $service{icmp_code} = $ICMP6->{ $data->{type} }->{ $data->{code} } || 'Any code';
        }
    }
    return \%service;
}

sub parse_one_static_route {
    my ($backup, $obj) = @_;
    my $data = $obj->{data};
    
    # Determine route type by checking the data type field
    my $route_type = $data->{type} // '';  # 'itf' for interface route, 'host' for gateway route, 'blackhole' for drop route
    
    # Get the network information
    my $network_ref = get_ref($backup, $data->{network});
    
    # Initialize variables
    my $destination_ip = '';
    my $netmask = '';
    my $ip_family = 'IPv4';
    my $gateway = '';
    my $interface = '';
    my $is_gateway_route = 0;
    my $is_interface_route = 0;
    my $is_blackhole_route = 0;
    
    # Extract destination IP and netmask from network object
    if ($network_ref->{type} eq 'network' || $network_ref->{type} eq 'interface_network') {
        # Network object
        if ($network_ref->{data}->{address} && $network_ref->{data}->{address} ne '0.0.0.0') {
            $destination_ip = $network_ref->{data}->{address};
            $netmask = cidr_to_netmask($network_ref->{data}->{netmask}) if $network_ref->{data}->{netmask};
            $ip_family = 'IPv4';
        } elsif ($network_ref->{data}->{address6} && $network_ref->{data}->{address6} ne '::') {
            $destination_ip = $network_ref->{data}->{address6};
            $netmask = $network_ref->{data}->{netmask6};
            $ip_family = 'IPv6';
        }
    } elsif ($network_ref->{type} eq 'host') {
        # Host object
        if ($network_ref->{data}->{address} && $network_ref->{data}->{address} ne '0.0.0.0') {
            $destination_ip = $network_ref->{data}->{address};
            $netmask = '255.255.255.255';  # Host route
            $ip_family = 'IPv4';
        } elsif ($network_ref->{data}->{address6} && $network_ref->{data}->{address6} ne '::') {
            $destination_ip = $network_ref->{data}->{address6};
            $netmask = '128';  # Host route for IPv6
            $ip_family = 'IPv6';
        }
    }
    
    # Determine if it's an interface route or gateway route
    if ($route_type eq 'itf') {
        # Interface route - use the provided interface name
        $is_interface_route = 1;
        my $mapped_route_interface = map_utm_interface_name_to_sfos($INTERFACE_ROUTE_NAME);
        $interface = $mapped_route_interface ne '' ? $mapped_route_interface : $INTERFACE_ROUTE_NAME;
    } elsif ($route_type eq 'host') {
        # Gateway route - get gateway IP
        $is_gateway_route = 1;
        my $gateway_ref = get_ref($backup, $data->{target});
        if ($gateway_ref) {
            if ($gateway_ref->{data}->{address} && $gateway_ref->{data}->{address} ne '0.0.0.0') {
                $gateway = $gateway_ref->{data}->{address};
            } elsif ($gateway_ref->{data}->{address6} && $gateway_ref->{data}->{address6} ne '::') {
                $gateway = $gateway_ref->{data}->{address6};
            }
        }
    } elsif ($route_type eq 'blackhole') {
        # Blackhole route - no gateway/interface binding required
        $is_blackhole_route = 1;
    }
    
    # Get metric (distance)
    my $metric = $data->{metric} || 0;
    # For blackhole routes, SFOS route storage does not persist distance; force distance=0 for blackhole export.
    my $distance = $is_blackhole_route ? 0 : $metric;
    
    # Get status
    my $status = ($data->{status} ? 'ON' : 'OFF');
    
    # Get comment/description
    my $description = escape_html($data->{comment} || '');
    
    # Check if route is valid
    if (!$destination_ip) {
        warn "Will not export static route $data->{name}: missing destination IP\n";
        return undef;
    }
    
    if (!$is_gateway_route && !$is_interface_route && !$is_blackhole_route) {
        warn "Will not export static route $data->{name}: unknown route type\n";
        return undef;
    }
    
    if ($is_interface_route && !$interface) {
        warn "Will not export static route $data->{name}: missing interface name (use -I option)\n";
        return undef;
    }
    
    if ($is_gateway_route && !$gateway) {
        warn "Will not export static route $data->{name}: missing gateway\n";
        return undef;
    }
    
    return {
        ip_family => $ip_family,
        destination_ip => $destination_ip,
        netmask => $netmask,
        gateway => $gateway,
        interface => $interface,
        is_gateway_route => $is_gateway_route,
        is_interface_route => $is_interface_route,
        distance => $distance,
        administrative_distance => $metric,
        description => $description, 
        status => $status,
        blackhole => ($is_blackhole_route ? 'Enable' : 'Disable'),
    };
}

sub extract_urls_from_domain_refs {
    my ($backup, $domain_refs) = @_;
    my @ret;
    for my $ref (@$domain_refs) {
        my $obj = get_ref $backup, $ref;
        push @ret, @{ $obj->{data}->{domain} };
    }
    return @ret;
}

sub remove_regex_domains {
    my (@domains) = @_;
    # SFOS URL Group entries validate as DOMAINNAME; keep only simple domain tokens (A-Za-z0-9.-).
    return grep { ! /[^a-zA-Z0-9.-]/ } @domains;
}

sub build_url_group {
    my ($full_name, $trunc_name, $type, @urls) = @_;
    return {
        name => $full_name,
        trunc_name => $trunc_name,
        type => $type,
        urls => [ map { url => $_ }, @urls ]
    };
}

sub split_domain_list_for_url_group {
    my ($n, $type, $full_name, $trunc_name, @urls) = @_;

    if (@urls <= $n) {
        return [ build_url_group $full_name, $trunc_name, $type, @urls ];
    } else {

        my $urls_split = split_array($n, \@urls);
        my @trunc_names = map { $trunc_name . ' ' . $_ } 1 .. @$urls_split;
        return [
            map {
                build_url_group $full_name, $trunc_names[$_], $type, @{$urls_split->[$_]}
            } (0..@$urls_split-1)
        ];
    }
}

sub parse_one_url_group {
    my ($backup, $obj) = @_;

    my $full_name = escape_html($obj->{data}->{name});
    my $trunc_name = trunc($full_name, 30);

    my @ret;

    my @allowlist = remove_regex_domains extract_urls_from_domain_refs(
        $backup, $obj->{data}->{url_whitelist});

    my @blocklist = remove_regex_domains extract_urls_from_domain_refs(
        $backup, $obj->{data}->{url_blacklist});

    if (@allowlist) {
        push @ret, @{
            split_domain_list_for_url_group(
                128, 'allow', $full_name, $trunc_name, @allowlist)
        };
    }

    if (@blocklist) {
        push @ret, @{
            split_domain_list_for_url_group(
                128, 'block', $full_name, $trunc_name, @blocklist)
        };
    }

    return \@ret;
}

sub parse_application_filter_policy {
    my ($backup, $obj) = @_;
    my $data = $obj->{data};
    return [] if !defined $data;

    return [{
        name => escape_trunc($data->{name} // $obj->{ref}),
        description => escape_html($data->{comment} // ''),
    }];
}

sub parse_one_ipsec_vpn_connection {
    my ($backup, $obj) = @_;
    my $data = $obj->{data};
    my $remote_gateway = get_ref($backup, $data->{remote_gateway});
    my $policy = get_ref($backup, $data->{policy});
    my $remote_auth = get_ref($backup, $remote_gateway->{data}->{authentication});

    die 'auth object is of wrong type' if ($remote_auth->{class} ne 'ipsec_remote_auth');

    my %vpn_id_types = (
        ipv4_address => 'IP Address',
        fqdn => 'DNS',
        user_fqdn => 'Email',
        from_certificate => 'DER ASN1 DN (X.509)',
        der_asn1_dn => 'DER ASN1 DN (X.509)',
    );

    my %auth_types = (
        psk => 'PresharedKey',
        rsa => 'RSAKey',
        x509 => 'DigitalCertificate',
    );

    my @any_networks = grep {
        is_any_network get_ref($backup, $_)
    } @{$obj->{data}->{networks}}, @{$remote_gateway->{data}->{networks}};

    if (@any_networks) {
        warn "Will not export IPSec VPN connection $data->{name}: can't use Any networks - found: @any_networks\n";
        return;
    }

    my $local_subnets = [
        map { network_name($backup, get_ref($backup, $_)) } @{$obj->{data}->{networks}}
    ];

    my $remote_networks = [
        map { network_name($backup, get_ref($backup, $_)) } @{$remote_gateway->{data}->{networks}}
    ];

    my $local_interface_source = '';
    if (defined $data->{interface} && $data->{interface} ne '') {
        my $local_interface_obj = get_ref($backup, $data->{interface});
        if ($local_interface_obj && $local_interface_obj->{data}) {
            $local_interface_source = $local_interface_obj->{data}->{name} // '';
        }
    }
    my $default_local_interface = map_utm_interface_name_to_sfos($DEFAULT_INTERFACE_NAME);
    my $resolved_local_interface = map_utm_interface_name_to_sfos($local_interface_source);
    $resolved_local_interface = $default_local_interface if $resolved_local_interface eq '';
    $resolved_local_interface = $DEFAULT_INTERFACE_NAME if $resolved_local_interface eq '';

    if ($local_interface_source ne '' && lc($local_interface_source) ne lc($resolved_local_interface)) {
        my $message = is_sfos_gateway_interface_name($local_interface_source)
            ? 'Normalized IPsec local interface name casing for SFOS export'
            : 'Mapped IPsec local interface to SFOS-compatible placeholder';
        add_warning('vpn-ipsec', $message, {
            name => $data->{name} // $obj->{ref},
            source_interface => $local_interface_source,
            mapped_interface => $resolved_local_interface,
        });
        increment_stat('vpn.ipsec.interface.mapped');
    } elsif ($local_interface_source eq '' && $resolved_local_interface ne '') {
        increment_stat('vpn.ipsec.interface.defaulted');
    }

    my $vpn = {
        name => sanitize_name($data->{name}),
        type => 'SiteToSite',
        description => $data->{comment},
        policy => sanitize_name($policy->{data}->{name}),
        auth_type => $auth_types{$remote_auth->{type}},
        # one of: PresharedKey DigitalCertificate RSAKey
        local_subnets => $local_subnets,
        remote_networks => $remote_networks,
        remote_host => get_ref($backup, $remote_gateway->{data}->{host})->{data}->{address},
        # TODO can we have multiple ipsec remote addresses on utm?
        status => ($data->{status} ? 'Active' : 'Inactive'),
        remote_id_type => $vpn_id_types{$remote_auth->{data}->{vpn_id_type}},
        remote_id => $remote_auth->{data}->{vpn_id},  # TODO fixme for rsa and cert
        # These should contain the local interface name, but interface names are different between UTM and SFOS!
        local_address => $resolved_local_interface,
        local_gateway => $resolved_local_interface,
    };

    for ($remote_auth->{type}) {
        if ($_ eq 'psk') {
            my $psk = $remote_auth->{data}->{psk};
            if (length $psk < 5) {
                warn "Will not export IPSec VPN connection $data->{name}: PSK too short - must be at least 5 characters\n";
                return undef;
            }
            $vpn->{auth_type} = 'PresharedKey';
            $vpn->{preshared_key} = $psk;
            my $confd_ipsec_advanced = $backup->{main}->{ipsec}->{advanced};
            $vpn->{local_id_type} = $vpn_id_types{$confd_ipsec_advanced->{psk_vpn_id_type}};
            $vpn->{local_id} = $confd_ipsec_advanced->{psk_vpn_id};

        } elsif ($_ eq 'rsa') {
            $vpn->{auth_type} = 'RSAKey';
            $vpn->{pubkey} = $remote_auth->{data}->{pubkey};
            my $local_auth = get_ref($backup, $backup->{main}->{ipsec}->{local_rsa});
            $vpn->{local_id_type} = $vpn_id_types{$local_auth->{data}->{vpn_id_type}};
            $vpn->{local_id} = $local_auth->{data}->{vpn_id};

        } elsif ($_ eq 'x509') {
            $vpn->{auth_type} = 'DigitalCertificate';
            my $cert;
            if ($remote_auth->{data}->{certificate} ne '') {
                $cert = get_ref($backup, $remote_auth->{data}->{certificate});
                if ($cert && $cert->{data}) {
                    $vpn->{certificate} = $cert->{data}->{certificate};
                }
            }
            if ($remote_auth->{data}->{vpn_id_type} eq 'from_certificate') {
                my $meta_ref = ($cert && $cert->{data}) ? $cert->{data}->{meta} : '';
                my $meta = get_ref($backup, $meta_ref);
                if ($meta && $meta->{data}) {
                    my $meta_vpn_id_type = $meta->{data}->{vpn_id_type} // 'der_asn1_dn';
                    $vpn->{remote_id_type} = $vpn_id_types{$meta_vpn_id_type} // $vpn_id_types{from_certificate};
                    $vpn->{remote_id} = $meta->{data}->{vpn_id};
                } else {
                    $vpn->{remote_id_type} = $vpn_id_types{from_certificate};
                    $vpn->{remote_id} = '';
                }
            } else {
                $vpn->{remote_id_type} = $vpn_id_types{$remote_auth->{data}->{vpn_id_type}};
                $vpn->{remote_id} = $remote_auth->{data}->{vpn_id};
            }
            my $confd_ipsec = $backup->{main}->{ipsec};
            my $local_rsa = get_ref($backup, $confd_ipsec->{local_rsa});
            $vpn->{local_id_type} = $vpn_id_types{$local_rsa->{data}->{vpn_id_type}};
            $vpn->{local_id} = $local_rsa->{data}->{vpn_id};
        }
    }

    if (not $vpn->{local_id}) {
        warn "Will not export IPSec VPN connection $data->{name}: does not have a local ID set!\n";
        return undef;
    }
    if (not $vpn->{remote_id}) {
        warn "Will not export IPSec VPN connection $data->{name}: does not have a remote ID set!\n";
        return undef;
    }
    return $vpn;
}

sub parse_ssl_tunnel_access_settings {
    my ($backup) = @_;

    my $s = $backup->{main}->{ssl_vpn};
    my $ip_assignment_pool = get_ref($backup, $s->{ip_assignment_pool});
    if ($ip_assignment_pool->{class} ne 'network' or $ip_assignment_pool->{type} ne 'network') {
        die 'auth object is of wrong type';
    };

    my $configured_cert_name = '';
    my $configured_cert = get_ref($backup, $s->{certificate});
    if ($configured_cert && $configured_cert->{data} && defined $configured_cert->{data}->{name}) {
        $configured_cert_name = sanitize_name($configured_cert->{data}->{name});
    }
    my $fn = resolve_ssl_server_certificate_name($backup, $s->{certificate});
    if ($fn eq '') {
        # Keep SSL tunnel settings exportable even when certificate material cannot be exported.
        # This preserves v0.8 behavior where SSL VPN entities were still generated.
        $fn = 'ApplianceCertificate';
        add_warning('ssl-vpn', 'Configured SSL VPN certificate is not exportable; using ApplianceCertificate fallback to preserve SSL VPN export continuity', {
            certificate_ref => $s->{certificate} // '',
            fallback => $fn,
        });
    }
    elsif ($configured_cert_name ne '' && $configured_cert_name ne $fn) {
        add_warning('ssl-vpn', 'Configured SSL VPN certificate is not exportable; using fallback exported certificate', {
            configured => $configured_cert_name,
            fallback => $fn,
        });
    }

    my $subnet_mask = cidr_to_netmask($ip_assignment_pool->{data}->{netmask});
    my $start_ip = first_assignable_ipv4($ip_assignment_pool->{data}->{address}, $subnet_mask);
    $start_ip = $ip_assignment_pool->{data}->{address} if $start_ip eq '';
    my $end_ip = last_assignable_ipv4($ip_assignment_pool->{data}->{address}, $subnet_mask);

    my %ret = (
        protocol => uc($s->{protocol}), # TODO map?
        certificate => $fn,
        hostname => undef, # FIXME OverrideHostname or HostorDNSName?
        port => $s->{port},
        start_ip => $start_ip,
        end_ip => $end_ip,
        subnet_mask => $subnet_mask,
        ipv6_lease => $ip_assignment_pool->{data}->{address6},
        ipv6_prefix => $ip_assignment_pool->{data}->{netmask6},
        lease_mode => 'IPv4', # TODO IPv4 or IPv6
        # TODO where are these defined?
        primary_dns_ipv4 => undef,
        secondary_dns_ipv4 => undef,
        primary_wins_ipv4 => undef,
        secondary_wins_ipv4 => undef,
        domain_name => undef,
        # }}}
        encryption_algorithm => $s->{encryption_algorithm},
        authentication_algorithm => $s->{authentication_algorithm},
        key_lifetime => $s->{datachannel_key_lifetime},
        compression => ($s->{compression} ? 'Enable' : 'Disable'),
        debug => ($s->{debug} ? 'Enable' : 'Disable'),
    );
    return \%ret;
}

sub sanitize_ssl_vpn_server_name {
    my $name = shift;
    return "" if (!defined $name || $name eq "");
    $name =~ s/[^A-Za-z0-9_]/_/g;
    if ($name =~ /\A[0-9_]/) {
        $name = "D" . $name;
    }
    return trunc($name, 50);
}

sub parse_one_ssl_vpn_server {
    my ($backup, $obj) = @_;

    my $ssl_vpn = $backup->{main}->{ssl_vpn};
    my $cert_obj = get_ref($backup, $ssl_vpn->{certificate});
    my $certificate_name = 'ApplianceCertificate';
    if ($cert_obj && $cert_obj->{data}) {
        $certificate_name = sanitize_name($cert_obj->{data}->{name});
    }

    my @any_networks = grep {
        is_any_network get_ref($backup, $_)
    } @{$obj->{data}->{local_networks}}, @{$obj->{data}->{remote_networks}};

    if (@any_networks) {
        warn "Will not export SSL VPN connection $obj->{data}->{name}: can't use Any networks - found: @any_networks\n";
        return undef;
    }

    my @local_networks = map { network_name($backup, get_ref($backup, $_)) } @{$obj->{data}->{local_networks}};
    my @remote_networks = map { network_name($backup, get_ref($backup, $_)) } @{$obj->{data}->{remote_networks}};

    my $sanitized_name = sanitize_ssl_vpn_server_name($obj->{data}->{name});

    return {
        name => $sanitized_name,
        static_ip => ($obj->{data}->{static_ip_status} ? 'Disable' : 'Enable'),
        local_networks => \@local_networks,
        remote_networks => \@remote_networks,
        status => ($obj->{data}->{status} ? 'On' : 'Off'),
        description => "Original Name: " . escape_html($obj->{data}->{name}),
        certificate => $certificate_name,
    };
}

sub make_ssl_vpn_client_config {
    my ($backup, $obj) = @_;
    my $ssl_vpn = $backup->{main}->{ssl_vpn};
    my $cert = get_ref($backup, $ssl_vpn->{certificate});
    my $srv_meta = get_ref($backup, $cert->{data}->{meta});
    my $srv_ca = get_ref($backup, $cert->{data}{ca});
    my $server_dn = $srv_meta->{data}->{subject};
    my $uses_gost = $srv_meta->{data}{public_key_algorithm} =~ /GOST/;

    my $engine = ($uses_gost ? 'gost' : '');
    my $cert_type = ($uses_gost ? 'x509_cert_gost' : 'x509_cert');
    my $user = get_ref($backup, $obj->{data}->{username});
    my $auth = get_ref($backup, $user->{data}{$cert_type});
    my $x509 = get_ref($backup, $auth->{data}{certificate});

    $engine = 'gost' if $ssl_vpn->{encryption_algorithm} eq 'gost89'
        || $ssl_vpn->{authentication_algorithm} eq 'gost-mac';

    my $hostname = get_ref($backup, $obj->{data}->{server_address})->{data}->{hostname};

    return {
        engine => $engine,
        certificate => $x509->{data}{certificate},
        key => $x509->{data}{key},
        ca_cert => $srv_ca->{data}{certificate},
        username => $user->{data}{name},
        password => $obj->{data}->{password},
        protocol => $ssl_vpn->{protocol},
        server_address => [ $hostname ],
        server_port => $ssl_vpn->{port},
        server_dn => $server_dn,
        compression => $ssl_vpn->{compression},
        encryption_algorithm => $ssl_vpn->{encryption_algorithm},
        authentication_algorithm => $ssl_vpn->{authentication_algorithm},
    };
}

sub parse_one_ssl_vpn_client {
    my ($backup, $obj) = @_;

    my $data = $obj->{data};
    my $apc_filename = sanitize_name($data->{name} . '.apc');

    my $client = {
        name => $data->{name},
        config_filename => $apc_filename,
        config_password => undef,
        http_proxy_server_enabled => $data->{proxy_status},
        http_proxy_server_name => $data->{proxy_host},
        http_proxy_server_port => $data->{proxy_port},
        http_proxy_server_auth_enabled => $data->{proxy_auth_status},
        http_proxy_server_username => $data->{proxy_auth_user},
        http_proxy_server_password => $data->{proxy_auth_pass},
        peerhost_enabled => undef, # TODO
        peerhost_name => undef,
        # description => undef,
        status => ($data->{status} ? 'On' : 'Off'),
    };
    my $apc = make_ssl_vpn_client_config($backup, $obj);
    my $extra_data = {$apc_filename => JSON->new->utf8->encode($apc)};
    return ($client, $extra_data);
}

sub parse_one_certificate {
    my ($backup, $obj) = @_;

    my $name = sanitize_name($obj->{data}->{name});
    my $cert_name = $name . '.pem';
    my $key_name = $name . '.key';

    my $ret = {
        name => $name,
        certificate_file => $cert_name,
        private_key_file => $key_name
    };

    my $extra_data = {
        $cert_name => $obj->{data}->{certificate},
        $key_name => $obj->{data}->{key} };

    return $ret, $extra_data;
}

sub parse_one_ipsec_vpn_profile {
    my ($backup, $obj) = @_;

    my %encr_alg = (
        null => 'None',
        des => 'DES',
        '3des' => '3DES',
        aes128 => 'AES128',
        aes192 => 'AES192',
        aes256 => 'AES256',
        twofish => 'TwoFish',
        blowfish => 'BlowFish',
        serpent => 'Serpent',
    );

    my %auth_alg = (
        md5 => 'MD5',
        sha1 => 'SHA1',
        sha2_256 => 'SHA2_256',
        sha2_384 => 'SHA2_384',
        sha2_512 => 'SHA2_512',
        # 'sha2_256_96', 'sha2_384_96', 'sha2_512_96' - unsupported in utm
    );

    my %dh_groups = (
        null => 'None',
        modp768 => '1(DH768)',
        modp1024 => '2(DH1024)',
        modp1536 => '5(DH1536)',
        modp2048 => '14(DH2048)',
        modp3072 => '15(DH3072)',
        modp4096 => '16(DH4096)',
        # these are not supported by UTM
        # '17(DH6144)',
        # '18(DH8192)',
        # '19(ecp256)',
        # '20(ecp384)',
        # '21(ecp521)',
        # '25(ecp192)',
        # '26(ecp224)',
        # '31(curve25519)',
    );

    my %pfs_groups = (
        %dh_groups,
        0 => 'SameasPhase-I',
    );

    return {
        name => sanitize_name($obj->{data}->{name}),
        description => $obj->{data}->{comment},
        compression => ($obj->{data}->{ipsec_compression} ? 'Disable' : 'Enable'),
        phase1_encr1 => $encr_alg{$obj->{data}->{ike_enc_alg}},
        phase1_auth1 => $auth_alg{$obj->{data}->{ike_auth_alg}},
        phase1_encr2 => undef,
        phase1_auth2 => undef,
        phase1_encr3 => undef,
        phase1_auth3 => undef,
        phase1_dh_groups => [ { name => $dh_groups{$obj->{data}->{ike_dh_group}} } ],
        phase1_key_life => $obj->{data}->{ike_sa_lifetime},
        # TODO hardcoded for now - can be one of: Disconnect/Hold/ReInitiate
        action_when_unreachable => 'Disconnect',
        phase2_encr1 => $encr_alg{$obj->{data}->{ipsec_enc_alg}},
        phase2_auth1 => $auth_alg{$obj->{data}->{ipsec_auth_alg}},
        phase2_encr2 => undef,
        phase2_auth2 => undef,
        phase2_encr3 => undef,
        phase2_auth3 => undef,
        phase2_key_life => $obj->{data}->{ipsec_sa_lifetime},
        phase2_pfs_group => $pfs_groups{$obj->{data}->{ipsec_pfs_group}},
    };
}

sub fill_html_template_from_data {
    my ($template_name, $template_data) = @_;

    if ($DEBUG >= 1) {
        my $template_data_json = '';
        eval {
            $template_data_json = JSON->new->canonical->encode($template_data);
            1;
        } or do {
            my $err = $@ // 'unknown error';
            chomp $err;
            $template_data_json = '{"error":"could not encode template data to json"}';
            warn "[debug1][template-parse] failed to serialize template_data for $template_name: $err\n";
        };
        warn "[debug1][template-parse] template=$template_name data=$template_data_json\n";
    }

    my $filename = $HTML_TEMPLATE_DIR . $template_name;
    my $template = HTML::Template->new(filename => $filename, utf8 => 1, debug => 0, die_on_bad_params => 0)
        or die "Template creation failed";
    
    $template_data = {} if ref $template_data ne 'HASH';
    $template_data->{api_version} = $CONTRACT_BASELINE;
    
    $template->param($template_data);
    my $output = $template->output;
    $output =~ s/^\s*(?:\n|$)//mg;
    chomp $output;
    return $output;
}

sub make_entities {
    my ($template_name, $template_data) = @_;
    my @ret;
    if (ref $template_data ne 'ARRAY') {
        $template_data = [ $template_data ];
    }
    for my $td (@$template_data) {
        push @ret, fill_html_template_from_data $template_name, $td;
    }
    return \@ret;
}

sub parse_url_groups_from_tags_and_sites {
    my ($tag_objs, $site_objs) = @_;

    my %tags = ();
    my @ret;

    for my $tag_obj (@$tag_objs) {
        $tags{$tag_obj->{ref}} //= {
            name => $tag_obj->{data}->{name},
            urls => []
        };
    }

    for my $site_obj (@$site_objs) {
        my @site_tag_refs = @{ $site_obj->{data}->{tags} };
        for my $tag_ref (@site_tag_refs) {
            push @{ $tags{$tag_ref}->{urls} }, $site_obj->{data}->{site};
        }
    }

    for my $tag_ref (keys %tags) {
        my $full_name = escape_html $tags{$tag_ref}->{name};
        my $trunc_name = trunc $full_name, 30;
        my $type = 'tag';
        my $urls = $tags{$tag_ref}->{urls};

        push @ret, @{
            split_domain_list_for_url_group(
                128, $type, $full_name, $trunc_name, @$urls)
        };
    }

    return \@ret;
}

sub parse_remote_access_pptp_configuration {
    my ($backup) = @_;
    # TODO can SFOS auth users against radius?
    my $remote_access = $backup->{main}->{remote_access};
    my $pptp = $remote_access->{pptp};
    my $advanced = $remote_access->{advanced};
    my $ip_assignment_pool = get_ref($backup, $pptp->{ip_assignment_pool});
    my $primary_dns = normalize_ipv4_or_empty($advanced->{msdns1});
    my $secondary_dns = normalize_ipv4_or_empty($advanced->{msdns2});

    my $fallback_dns = '';
    if ($ip_assignment_pool && $ip_assignment_pool->{data}) {
        my $pool_netmask = cidr_to_netmask($ip_assignment_pool->{data}->{netmask});
        $fallback_dns = first_assignable_ipv4($ip_assignment_pool->{data}->{address}, $pool_netmask);
    }
    if ($primary_dns eq '' && $fallback_dns ne '') {
        $primary_dns = $fallback_dns;
        add_warning('pptp', 'Primary DNS was invalid/missing in UTM source and was replaced with first assignable pool IP', {
            fallback_dns => $fallback_dns,
        });
    }
    if ($primary_dns eq '' && $secondary_dns ne '') {
        $primary_dns = $secondary_dns;
        $secondary_dns = '';
        add_warning('pptp', 'Promoted secondary DNS to primary DNS because primary DNS was invalid/missing', {
            promoted_dns => $primary_dns,
        });
    }
    if ($primary_dns eq '') {
        $primary_dns = '8.8.8.8';
        add_warning('pptp', 'No valid DNS could be derived from source data; using conservative fallback DNS', {
            fallback_dns => $primary_dns,
        });
    }
    $secondary_dns = '' if $secondary_dns eq $primary_dns;

    return {
        general_settings => 'Enable',
        # TODO ips can be assigned by radius too - not supported yet
        ip_assignment_mode => $pptp->{ip_assignment_mode},
        start_ip => undef,
        end_ip => undef,
        lease_ip_from_radius => 'Disable', # Enable Disable
        primary_dns => $primary_dns,
        secondary_dns => $secondary_dns,
        primary_wins => $advanced->{mswins1},
        secondary_wins => $advanced->{mswins2},
    } if !$ip_assignment_pool;

    my ($start_ip, $end_ip) = calculate_ip_range(
        $ip_assignment_pool->{data}->{address},
        cidr_to_netmask($ip_assignment_pool->{data}->{netmask}));

    return {
        general_settings => 'Enable',
        # TODO ips can be assigned by radius too - not supported yet
        ip_assignment_mode => $pptp->{ip_assignment_mode},
        start_ip => $start_ip,
        end_ip => $end_ip,
        lease_ip_from_radius => 'Disable', # Enable Disable
        primary_dns => $primary_dns,
        secondary_dns => $secondary_dns,
        primary_wins => $advanced->{mswins1},
        secondary_wins => $advanced->{mswins2},
    };
}

sub parse_remote_access_ssl_vpn {
    my ($backup, $obj) = @_;

    return {
        name => $obj->{data}->{name},
        description => $obj->{data}->{comment},
        use_as_default_gw => 'Off',
        permitted_network_resources_ipv4 => [
            map { network_name($backup, get_ref($backup, $_)) } @{$obj->{data}->{networks}}
        ],
        disconnect_idle_clients => 'On',
        override_global_timeout_minutes => 15
    };
}

sub calculate_ip_range {
    my ($ip, $netmask) = @_;
    my $nip = inet_aton $ip;
    my $nmask = inet_aton $netmask;
    my $first = inet_ntoa ($nip & $nmask);
    my $last = inet_ntoa ($nip | ~$nmask);

    return ($first, $last);
}

sub first_assignable_ipv4 {
    my ($ip, $netmask) = @_;
    return '' if !is_valid_ipv4_literal($ip) || !is_valid_ipv4_literal($netmask);
    my $nip = unpack 'N', inet_aton($ip);
    my $nmask = unpack 'N', inet_aton($netmask);
    my $network = $nip & $nmask;
    my $broadcast = $network | (~$nmask & 0xFFFFFFFF);
    my $first_host = ($network < $broadcast) ? ($network + 1) : $network;
    return inet_ntoa(pack 'N', $first_host);
}

sub last_assignable_ipv4 {
    my ($ip, $netmask) = @_;
    return '' if !is_valid_ipv4_literal($ip) || !is_valid_ipv4_literal($netmask);
    my $nip = unpack 'N', inet_aton($ip);
    my $nmask = unpack 'N', inet_aton($netmask);
    my $network = $nip & $nmask;
    my $broadcast = $network | (~$nmask & 0xFFFFFFFF);
    my $last_host = ($network < $broadcast) ? ($broadcast - 1) : $broadcast;
    return inet_ntoa(pack 'N', $last_host);
}

sub ipv4_from_optional_prefix {
    my ($value) = @_;
    return '' if !defined $value || $value eq '';
    return $value if is_valid_ipv4_literal($value);
    if ($value =~ /^(\d{1,3}(?:\.\d{1,3}){3})\/\d+$/) {
        return $1 if is_valid_ipv4_literal($1);
    }
    return '';
}

sub subnet_mask_from_optional_prefix {
    my ($value) = @_;
    return '' if !defined $value || $value eq '';
    return '' if $value !~ /\/(\d{1,2})$/;
    my $prefix = $1;
    return '' if $prefix < 0 || $prefix > 32;
    return cidr_to_dotted_decimal($prefix);
}

sub normalize_dhcp_subnet_mask {
    my ($value) = @_;
    return '' if !defined $value || $value eq '';
    if ($value =~ /^\d+$/ && $value >= 0 && $value <= 32) {
        return cidr_to_dotted_decimal($value);
    }
    if (is_valid_ipv4_literal($value)) {
        my $prefix = ipv4_prefixlen_from_netmask($value);
        return $value if $prefix ne '';
    }
    return '';
}

sub find_primary_interface_for_address_ref {
    my ($backup, $address_ref) = @_;
    return undef if !defined $address_ref || $address_ref eq '';
    for my $obj (values %{ $backup->{objects} // {} }) {
        next if !$obj || ($obj->{class} // '') ne 'itfparams' || ($obj->{type} // '') ne 'primary';
        next if !$obj->{data};
        next if ($obj->{data}->{primary_address} // '') ne $address_ref;
        return $obj;
    }
    return undef;
}

sub resolve_dhcp_interface_context {
    my ($backup, $interface_ref) = @_;
    my %context = (
        interface_name => '',
        interface_ip => '',
        subnet_mask => '',
        gateway => '',
    );

    return \%context if !defined $interface_ref || $interface_ref eq '' || $interface_ref eq '-1';
    my $if_obj = get_ref($backup, $interface_ref);
    return \%context if !$if_obj || !$if_obj->{data};
    my $if_data = $if_obj->{data};

    $context{interface_name} = $if_data->{name} // '';
    $context{interface_ip} = normalize_ipv4_or_empty(ipv4_from_optional_prefix($if_data->{address} // ''));
    $context{subnet_mask} = normalize_dhcp_subnet_mask($if_data->{subnet_mask} // $if_data->{subnetmask} // $if_data->{netmask} // '');
    $context{subnet_mask} = subnet_mask_from_optional_prefix($if_data->{address} // '') if $context{subnet_mask} eq '';
    $context{gateway} = normalize_ipv4_or_empty(ipv4_from_optional_prefix($if_data->{default_gateway_address} // $if_data->{default_gateway} // $if_data->{gateway} // ''));

    my $primary_obj;
    if (($if_obj->{class} // '') eq 'itfparams' && ($if_obj->{type} // '') eq 'primary') {
        $primary_obj = $if_obj;
    } else {
        my $primary_ref = $if_data->{primary}
            // $if_data->{primary_ref}
            // $if_data->{primary_address}
            // $if_data->{itfparams}
            // $if_data->{interface}
            // '';
        if ($primary_ref ne '') {
            my $candidate = get_ref($backup, $primary_ref);
            if ($candidate && ($candidate->{class} // '') eq 'itfparams' && ($candidate->{type} // '') eq 'primary') {
                $primary_obj = $candidate;
            }
        }
        $primary_obj //= find_primary_interface_for_address_ref($backup, $interface_ref);
    }

    if ($primary_obj && $primary_obj->{data}) {
        my $primary_data = $primary_obj->{data};
        if (($primary_data->{name} // '') ne '' && ($context{interface_name} eq '' || $context{interface_name} =~ /^\d{1,3}(?:\.\d{1,3}){3}\/\d+$/)) {
            $context{interface_name} = $primary_data->{name};
        }
        my $primary_ip = normalize_ipv4_or_empty(ipv4_from_optional_prefix($primary_data->{address} // ''));
        $context{interface_ip} = $primary_ip if $context{interface_ip} eq '' && $primary_ip ne '';
        my $primary_mask = normalize_dhcp_subnet_mask($primary_data->{subnet_mask} // $primary_data->{subnetmask} // $primary_data->{netmask} // '');
        $primary_mask = subnet_mask_from_optional_prefix($primary_data->{address} // '') if $primary_mask eq '';
        $context{subnet_mask} = $primary_mask if $context{subnet_mask} eq '' && $primary_mask ne '';
        my $primary_gateway = normalize_ipv4_or_empty(ipv4_from_optional_prefix($primary_data->{default_gateway_address} // $primary_data->{default_gateway} // ''));
        $context{gateway} = $primary_gateway if $context{gateway} eq '' && $primary_gateway ne '';

        my $primary_addr_ref = $primary_data->{primary_address} // '';
        if ($primary_addr_ref ne '') {
            my $addr_obj = get_ref($backup, $primary_addr_ref);
            if ($addr_obj && $addr_obj->{data}) {
                my $addr_data = $addr_obj->{data};
                my $addr_ip = normalize_ipv4_or_empty(ipv4_from_optional_prefix($addr_data->{address} // ''));
                $context{interface_ip} = $addr_ip if $context{interface_ip} eq '' && $addr_ip ne '';
                my $addr_mask = normalize_dhcp_subnet_mask($addr_data->{subnet_mask} // $addr_data->{subnetmask} // $addr_data->{netmask} // '');
                $addr_mask = subnet_mask_from_optional_prefix($addr_data->{address} // '') if $addr_mask eq '';
                $context{subnet_mask} = $addr_mask if $context{subnet_mask} eq '' && $addr_mask ne '';
            }
        }
    }

    return \%context;
}

sub ipv4_to_int {
    my ($ip) = @_;
    return undef if !is_valid_ipv4_literal($ip);
    return unpack 'N', inet_aton($ip);
}

sub int_to_ipv4 {
    my ($value) = @_;
    return '' if !defined $value || $value < 0 || $value > 0xFFFFFFFF;
    return inet_ntoa(pack 'N', $value);
}

sub parse_ipv4_lease_range_bounds {
    my ($range) = @_;
    return undef if !defined $range || $range eq '';
    return undef if $range !~ /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$/;
    my ($start_ip, $end_ip) = ($1, $2);
    my $start_int = ipv4_to_int($start_ip);
    my $end_int = ipv4_to_int($end_ip);
    return undef if !defined $start_int || !defined $end_int || $start_int > $end_int;
    return {
        start_ip => $start_ip,
        end_ip => $end_ip,
        start_int => $start_int,
        end_int => $end_int,
    };
}

sub ipv4_subnet_bounds_from_ip_and_mask {
    my (%args) = @_;
    my $interface_ip = $args{interface_ip} // '';
    my $subnet_mask = $args{subnet_mask} // '';
    return undef if !is_valid_ipv4_literal($interface_ip) || !is_valid_ipv4_literal($subnet_mask);
    my $ip_int = ipv4_to_int($interface_ip);
    my $mask_int = ipv4_to_int($subnet_mask);
    return undef if !defined $ip_int || !defined $mask_int;

    my $network_int = $ip_int & $mask_int;
    my $broadcast_int = $network_int | (~$mask_int & 0xFFFFFFFF);
    return {
        network_int => $network_int,
        broadcast_int => $broadcast_int,
        network_ip => int_to_ipv4($network_int),
        broadcast_ip => int_to_ipv4($broadcast_int),
    };
}

sub ipv4_is_within_subnet_bounds {
    my (%args) = @_;
    my $ip = $args{ip} // '';
    my $subnet_bounds = $args{subnet_bounds};
    return 0 if $ip eq '' || ref($subnet_bounds) ne 'HASH';
    return 0 if !defined $subnet_bounds->{network_int} || !defined $subnet_bounds->{broadcast_int};
    my $ip_int = ipv4_to_int($ip);
    return 0 if !defined $ip_int;
    return ($ip_int >= $subnet_bounds->{network_int} && $ip_int <= $subnet_bounds->{broadcast_int}) ? 1 : 0;
}

sub warn_dhcp_lease_ranges_outside_interface_subnet {
    my (%args) = @_;
    my $server_name = $args{server_name} // '';
    my $interface_name = $args{interface_name} // '';
    my $interface_ref = $args{interface_ref} // '';
    my $interface_ip = $args{interface_ip} // '';
    my $subnet_mask = $args{subnet_mask} // '';
    my $lease_ranges = ensure_arrayref($args{lease_ranges});

    return [] if !@$lease_ranges;
    my $subnet_bounds = ipv4_subnet_bounds_from_ip_and_mask(
        interface_ip => $interface_ip,
        subnet_mask => $subnet_mask,
    );
    return [] if !$subnet_bounds;

    my @out_of_subnet_ranges;
    for my $range (@$lease_ranges) {
        next if !defined $range || $range eq '';
        my $bounds = parse_ipv4_lease_range_bounds($range);
        next if !$bounds;
        next if $bounds->{start_int} >= $subnet_bounds->{network_int} && $bounds->{end_int} <= $subnet_bounds->{broadcast_int};
        push @out_of_subnet_ranges, $range;
    }
    return [] if !@out_of_subnet_ranges;

    add_warning('dhcp-range', 'DHCP lease ranges do not match resolved interface subnet; export keeps DHCP disabled for import safety', {
        server => $server_name,
        interface => $interface_name,
        interface_ref => $interface_ref,
        interface_ip => $interface_ip,
        subnet_mask => $subnet_mask,
        interface_subnet => $subnet_bounds->{network_ip} . '-' . $subnet_bounds->{broadcast_ip},
        offending_ranges => join(',', @out_of_subnet_ranges),
    });
    increment_stat('dhcp.range.subnet_mismatch');
    return \@out_of_subnet_ranges;
}

sub split_ipv4_lease_range_for_reserved_ips {
    my (%args) = @_;
    my $server_name = $args{server_name} // '';
    my $range = $args{range} // '';
    my $reserved_ips = ensure_arrayref($args{reserved_ips});

    my $bounds = parse_ipv4_lease_range_bounds($range);
    return [$range] if !$bounds;

    my %seen_reserved;
    my @reserved_ints;
    for my $raw_reserved_ip (@$reserved_ips) {
        next if !defined $raw_reserved_ip || $raw_reserved_ip eq '';
        my $candidate = normalize_ipv4_or_empty(ipv4_from_optional_prefix($raw_reserved_ip));
        next if $candidate eq '' || $seen_reserved{$candidate}++;
        my $candidate_int = ipv4_to_int($candidate);
        push @reserved_ints, $candidate_int if defined $candidate_int;
    }
    @reserved_ints = sort { $a <=> $b } @reserved_ints;

    my @hit_reserved_ints = grep { $_ >= $bounds->{start_int} && $_ <= $bounds->{end_int} } @reserved_ints;
    return [$range] if !@hit_reserved_ints;

    my @segments = ({ start => $bounds->{start_int}, end => $bounds->{end_int} });
    for my $reserved_int (@hit_reserved_ints) {
        my @next_segments;
        for my $segment (@segments) {
            if ($reserved_int < $segment->{start} || $reserved_int > $segment->{end}) {
                push @next_segments, $segment;
                next;
            }
            push @next_segments, { start => $segment->{start}, end => $reserved_int - 1 } if $reserved_int > $segment->{start};
            push @next_segments, { start => $reserved_int + 1, end => $segment->{end} } if $reserved_int < $segment->{end};
        }
        @segments = @next_segments;
        last if !@segments;
    }

    my @normalized_ranges = map { int_to_ipv4($_->{start}) . '-' . int_to_ipv4($_->{end}) } @segments;
    if (@normalized_ranges) {
        add_warning('dhcp-range', 'Adjusted DHCP lease range to exclude reserved IPs incompatible with SFOS', {
            server => $server_name,
            original_range => $range,
            reserved_ips => join(',', map { int_to_ipv4($_) } @hit_reserved_ints),
            resulting_ranges => join(',', @normalized_ranges),
        });
    } else {
        add_warning('dhcp-range', 'Removed DHCP lease range because reserved IPs consumed the full range', {
            server => $server_name,
            original_range => $range,
            reserved_ips => join(',', map { int_to_ipv4($_) } @hit_reserved_ints),
        });
    }
    return \@normalized_ranges;
}

sub resolve_utm_dhcp_option_ipv4_value {
    my (%args) = @_;
    my $backup = $args{backup};
    my $data = $args{data};
    return '' if ref($data) ne 'HASH';

    my $address_ref = $data->{address} // '';
    my $ip = normalize_ipv4_or_empty(ipv4_from_optional_prefix($address_ref));
    return $ip if $ip ne '';

    my $address_obj = get_ref($backup, $address_ref);
    return '' if !$address_obj || ref($address_obj->{data}) ne 'HASH';
    my $candidate = normalize_ipv4_or_empty(ipv4_from_optional_prefix($address_obj->{data}->{address} // ''));
    return $candidate;
}

sub collect_dhcp_server_option_projection {
    my (%args) = @_;
    my $backup = $args{backup};
    my $server_name = $args{server_name} // '';
    my $server_ref = $args{server_ref} // '';

    my $projection = {
        boot_server => '',
        boot_file => '',
        dhcp_options => [],
    };
    my %seen_options;

    for my $obj (values %{ $backup->{objects} // {} }) {
        next if !$obj || ($obj->{class} // '') ne 'dhcp' || ($obj->{type} // '') ne 'option';
        next if ref($obj->{data}) ne 'HASH';
        my $data = $obj->{data};
        my $status = exists $data->{status} ? $data->{status} : 1;
        next if !is_true($status);
        next if ($data->{scope} // '') ne 'server';

        my $matches_server = 0;
        if ($server_ref ne '') {
            for my $candidate_ref (@{ensure_arrayref($data->{server})}) {
                if (($candidate_ref // '') eq $server_ref) {
                    $matches_server = 1;
                    last;
                }
            }
        }
        if (!$matches_server) {
            my $dhcp_name = $data->{dhcp_name} // '';
            $matches_server = 1 if $dhcp_name ne '' && $dhcp_name eq $server_name;
        }
        next if !$matches_server;

        my $code = $data->{code};
        if (!defined $code || $code !~ /^-?\d+$/) {
            add_warning('dhcp-server', 'Skipping DHCP option because code is not a valid integer', {
                server => $server_name,
                option_ref => $obj->{ref} // '',
                code => defined $code ? $code : '',
            });
            increment_stat('dhcp.server.option.skipped.invalid_code');
            next;
        }
        $code = int($code);

        my $utm_type = lc($data->{type} // '');
        my $option_type = '';
        my $option_value = '';
        if ($utm_type eq 'ip-address') {
            $option_type = 'IPAddress';
            $option_value = resolve_utm_dhcp_option_ipv4_value(
                backup => $backup,
                data => $data,
            );
        } elsif ($utm_type eq 'text' || $utm_type eq 'string') {
            $option_type = 'String';
            $option_value = $data->{text} // $data->{string} // '';
        } elsif ($utm_type eq 'integer') {
            $option_type = 'Four_Byte';
            $option_value = defined $data->{integer} ? $data->{integer} : '';
        } else {
            add_warning('dhcp-server', 'Skipping DHCP option with unsupported UTM option type for SFOS export', {
                server => $server_name,
                option_ref => $obj->{ref} // '',
                code => $code,
                option_type => $data->{type} // '',
            });
            increment_stat('dhcp.server.option.skipped.unsupported_type');
            next;
        }
        if ($option_value eq '') {
            add_warning('dhcp-server', 'Skipping DHCP option because no SFOS-compatible option value could be derived', {
                server => $server_name,
                option_ref => $obj->{ref} // '',
                code => $code,
                option_type => $data->{type} // '',
            });
            increment_stat('dhcp.server.option.skipped.empty_value');
            next;
        }

        my $normalized_boot_value = $option_value;
        if ($normalized_boot_value =~ /^"(.*)"$/) {
            $normalized_boot_value = $1;
        }
        if ($code == -1) {
            if ($projection->{boot_server} eq '') {
                $projection->{boot_server} = $normalized_boot_value;
            }
            next;
        }
        if ($code == -2) {
            if ($projection->{boot_file} eq '') {
                $projection->{boot_file} = $normalized_boot_value;
            }
            next;
        }
        if ($code < 1 || $code > 254) {
            add_warning('dhcp-server', 'Skipping DHCP option because code is out of SFOS supported range', {
                server => $server_name,
                option_ref => $obj->{ref} // '',
                code => $code,
            });
            increment_stat('dhcp.server.option.skipped.code_range');
            next;
        }

        my $option_name = $data->{dhcp_name} // '';
        if ($option_name eq '' || $option_name eq $server_name) {
            $option_name = "Option $code";
        }
        my $dedupe_key = join('|', $code, $option_type, $option_value);
        next if $seen_options{$dedupe_key}++;
        push @{ $projection->{dhcp_options} }, {
            option_name => escape_trunc($option_name),
            option_code => $code,
            option_type => $option_type,
            option_value => escape_html($option_value),
        };
    }

    return $projection;
}

sub resolve_ssl_server_certificate_name {
    my ($backup, $certificate_ref) = @_;
    my $candidate = get_ref($backup, $certificate_ref);
    if ($candidate && $candidate->{class} eq 'ca' && $candidate->{type} eq 'host_key_cert' && $candidate->{data}) {
        my $data = $candidate->{data};
        if (($data->{name} // '') ne '' && ($data->{certificate} // '') ne '' && ($data->{key} // '') ne '') {
            return sanitize_name($data->{name});
        }
    }

    for my $obj (values %{ $backup->{objects} }) {
        next if !$obj || $obj->{class} ne 'ca' || $obj->{type} ne 'host_key_cert' || !$obj->{data};
        my $data = $obj->{data};
        next if ($data->{name} // '') eq '' || ($data->{certificate} // '') eq '' || ($data->{key} // '') eq '';
        return sanitize_name($data->{name});
    }

    return '';
}

sub ref_to_object_name {
    my ($backup, $ref) = @_;
    return '' if !defined $ref || $ref eq '';
    my $obj = get_ref($backup, $ref);
    return '' if !$obj;
    return $obj->{data}->{name} // '';
}

sub ref_to_service_name {
    my ($backup, $ref) = @_;
    return '' if !defined $ref || $ref eq '';
    my $obj = get_ref($backup, $ref);
    return '' if !$obj;
    return '' if $obj->{type} eq 'any';
    return escape_trunc($obj->{data}->{name} // '');
}

sub normalize_atp_threat_exception_candidate {
    my ($value) = @_;
    return '' if !defined $value;

    my $normalized = "$value";
    $normalized =~ s/\s+//g;
    return '' if $normalized eq '';

    # UTM threat exceptions are entered as "Threat URL", while SFOS accepts
    # host/domain-like threat identifiers. Normalize URL-like values first.
    $normalized =~ s{^[A-Za-z][A-Za-z0-9+.-]*://}{};
    $normalized =~ s{[/?#].*$}{};
    $normalized =~ s/:\d+$// if $normalized !~ /:/ || $normalized =~ /^[A-Za-z0-9_.-]+:\d+$/;
    $normalized =~ s/\.$//;

    return $normalized;
}

sub atp_threat_exception_rejection_reason {
    my ($value) = @_;
    return 'value is empty after normalization' if !defined $value || $value eq '';

    if (is_valid_ipv4_literal($value)) {
        return 'IPv4 value is explicitly disallowed by SFOS ATP validation'
            if $value eq '0.0.0.0' || $value eq '127.0.0.1' || $value eq '255.255.255.255';
        return '';
    }

    # Mirrors SFOS ATP validation fallback pattern used for identifiers/domains.
    return '' if $value =~ /^\w(?:[-.]?\w)*$/;
    return 'value does not match SFOS ATP threat format (IPv4/domain/identifier)';
}

sub parse_atp {
    my ($backup) = @_;
    my $aptp = $backup->{main}->{aptp};
    return [] if !defined $aptp || !exists $aptp->{status};

    my $enabled = is_true($aptp->{status});
    my $policy = ($aptp->{policy} && $aptp->{policy} eq 'drop') ? 'Log and Drop' : 'Log Only';
    my $inspect_content = 'untrusted';
    my $inspect_raw = lc($aptp->{inspect_content} // $aptp->{inspectcontent} // '');
    if ($inspect_raw eq 'all' || $inspect_raw eq 'untrusted') {
        $inspect_content = $inspect_raw;
    } elsif (is_true($aptp->{scan_all}) || is_true($aptp->{all_content}) || is_true($aptp->{all_traffic})) {
        $inspect_content = 'all';
    }
    my @host_exceptions;
    my %seen_host_exception;
    for my $ref (@{ensure_arrayref($aptp->{transparent_skip})}) {
        my $resolved_names = resolve_atp_host_exception_names($backup, $ref);
        if (!@$resolved_names) {
            my $obj = get_ref($backup, $ref);
            add_warning('atp', 'ATP host exception reference could not be resolved; skipped', {
                reference => (defined $ref ? $ref : ''),
                class => (($obj && ref($obj) eq 'HASH') ? ($obj->{class} // '') : ''),
                type => (($obj && ref($obj) eq 'HASH') ? ($obj->{type} // '') : ''),
            });
            increment_stat('atp.host_exception_unresolved_ref');
            next;
        }

        for my $name (@$resolved_names) {
            next if !defined $name || $name eq '';
            if (is_ipv6_firewall_network_name($name)) {
                add_warning('atp', 'Dropped IPv6 ATP host exception to satisfy SFOS ATP host exception validation', {
                    reference => $ref,
                    host_exception => $name,
                });
                increment_stat('atp.host_exception_ipv6_dropped');
                next;
            }
            next if $seen_host_exception{$name}++;
            push @host_exceptions, { name => $name };
        }
    }

    my @threat_exceptions;
    my %seen_threat_exception;
    for my $modifier_value (@{ensure_arrayref($aptp->{rule_modifiers})}) {
        my $candidate = $modifier_value;

        # Real UTM stores aptp->rule_modifiers as BLOB strings, but keep
        # fixture/backward compatibility for unexpected REF_* inputs.
        if (defined $modifier_value && $modifier_value =~ /^REF_/) {
            my $modifier = get_ref($backup, $modifier_value);
            if ($modifier && $modifier->{data}) {
                $candidate = $modifier->{data}->{name} // $modifier_value;
            }
        }

        my $normalized = normalize_atp_threat_exception_candidate($candidate);
        my $reject_reason = atp_threat_exception_rejection_reason($normalized);
        if ($reject_reason ne '') {
            add_warning('atp', 'Dropped ATP threat exception that is not SFOS-compatible', {
                value => (defined $modifier_value ? $modifier_value : ''),
                normalized_value => $normalized,
                reason => $reject_reason,
            });
            increment_stat('atp.threat_exception_dropped');
            next;
        }

        next if $seen_threat_exception{$normalized}++;
        push @threat_exceptions, { name => escape_trunc($normalized) };
    }

    if (!$enabled && (@host_exceptions || @threat_exceptions)) {
        add_warning('atp', 'UTM ATP is disabled; SFOS may ignore ATP exceptions unless ATP is enabled', {
            host_exception_count => scalar(@host_exceptions),
            threat_exception_count => scalar(@threat_exceptions),
        });
    }

    increment_stat('atp');
    return {
        status => bool_to_enable_disable($enabled),
        inspect_content => $inspect_content,
        policy => $policy,
        host_exceptions => \@host_exceptions,
        threat_exceptions => \@threat_exceptions,
    };
}

sub normalize_schedule_time_slot {
    my ($raw_value) = @_;
    return '' if !defined $raw_value || $raw_value eq '';
    return '' if $raw_value !~ /^(\d{1,2}):(\d{2})(?::\d{2})?$/;
    my ($hour, $minute) = ($1 + 0, $2 + 0);
    return '' if $hour < 0 || $hour > 23 || $minute < 0 || $minute > 59;

    my %allowed = map { $_ => 1 } (0, 15, 30, 45, 59);
    if (!$allowed{$minute}) {
        $minute = int($minute / 15) * 15;
    }
    return sprintf('%02d:%02d', $hour, $minute);
}

sub normalize_schedule_date {
    my ($raw_value) = @_;
    return '' if !defined $raw_value || $raw_value eq '';
    return $raw_value if $raw_value =~ /^\d{4}-\d{2}-\d{2}$/;
    if ($raw_value =~ /^(\d{4})\/(\d{2})\/(\d{2})$/) {
        return "$1-$2-$3";
    }
    if ($raw_value =~ /^(\d{2})\.(\d{2})\.(\d{4})$/) {
        return "$3-$2-$1";
    }
    return '';
}

sub normalize_schedule_weekday_label {
    my ($raw_value) = @_;
    return '' if !defined $raw_value || $raw_value eq '';
    my $value = lc($raw_value);
    $value =~ s/^\s+|\s+$//g;
    $value =~ s/_/ /g;
    $value =~ s/\s+/ /g;
    my %map = (
        sun => 'Sunday',
        sunday => 'Sunday',
        mon => 'Monday',
        monday => 'Monday',
        tue => 'Tuesday',
        tues => 'Tuesday',
        tuesday => 'Tuesday',
        wed => 'Wednesday',
        wednesday => 'Wednesday',
        thu => 'Thursday',
        thur => 'Thursday',
        thurs => 'Thursday',
        thursday => 'Thursday',
        fri => 'Friday',
        friday => 'Friday',
        sat => 'Saturday',
        saturday => 'Saturday',
        'week days' => 'Week Days',
        weekdays => 'Week Days',
        weekday => 'Week Days',
        'weekdays including saturday' => 'Weekdays Including Saturday',
        'all days' => 'All Days of week',
        'all days of week' => 'All Days of week',
        all => 'All Days of week',
    );
    return $map{$value} // '';
}

sub normalize_schedule_weekday_labels {
    my ($raw_values) = @_;
    my @labels;
    for my $raw (@{ ensure_arrayref($raw_values) }) {
        my $label = normalize_schedule_weekday_label($raw);
        push @labels, $label if $label ne '';
    }
    my %seen;
    @labels = grep { !$seen{$_}++ } @labels;
    return [] if !@labels;

    my %label_set = map { $_ => 1 } @labels;
    if (
        $label_set{Monday}
        && $label_set{Tuesday}
        && $label_set{Wednesday}
        && $label_set{Thursday}
        && $label_set{Friday}
        && $label_set{Saturday}
        && $label_set{Sunday}
    ) {
        return ['All Days of week'];
    }
    if (
        $label_set{Monday}
        && $label_set{Tuesday}
        && $label_set{Wednesday}
        && $label_set{Thursday}
        && $label_set{Friday}
        && !$label_set{Saturday}
        && !$label_set{Sunday}
    ) {
        return ['Week Days'];
    }
    if (
        $label_set{Monday}
        && $label_set{Tuesday}
        && $label_set{Wednesday}
        && $label_set{Thursday}
        && $label_set{Friday}
        && $label_set{Saturday}
        && !$label_set{Sunday}
    ) {
        return ['Weekdays Including Saturday'];
    }

    my %order = (
        Sunday => 1,
        Monday => 2,
        Tuesday => 3,
        Wednesday => 4,
        Thursday => 5,
        Friday => 6,
        Saturday => 7,
        'Week Days' => 8,
        'Weekdays Including Saturday' => 9,
        'All Days of week' => 10,
    );
    @labels = sort { ($order{$a} // 100) <=> ($order{$b} // 100) || $a cmp $b } @labels;
    return \@labels;
}

sub expand_schedule_weekday_labels {
    my ($labels) = @_;
    my @expanded;
    for my $label (@{ensure_arrayref($labels)}) {
        if ($label eq 'All Days of week') {
            push @expanded, qw(Sunday Monday Tuesday Wednesday Thursday Friday Saturday);
        } elsif ($label eq 'Week Days') {
            push @expanded, qw(Monday Tuesday Wednesday Thursday Friday);
        } elsif ($label eq 'Weekdays Including Saturday') {
            push @expanded, qw(Monday Tuesday Wednesday Thursday Friday Saturday);
        } elsif ($label =~ /^(?:Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday)$/) {
            push @expanded, $label;
        }
    }
    my %seen;
    @expanded = grep { !$seen{$_}++ } @expanded;
    return \@expanded;
}

sub shift_schedule_weekday_labels_forward {
    my ($labels) = @_;
    my %next_day = (
        Sunday => 'Monday',
        Monday => 'Tuesday',
        Tuesday => 'Wednesday',
        Wednesday => 'Thursday',
        Thursday => 'Friday',
        Friday => 'Saturday',
        Saturday => 'Sunday',
    );
    my @expanded = @{ expand_schedule_weekday_labels($labels) };
    my @shifted = map { $next_day{$_} // () } @expanded;
    my %seen;
    @shifted = grep { !$seen{$_}++ } @shifted;
    return \@shifted;
}

sub parse_one_schedule {
    my ($backup, $obj, $opts) = @_;
    $opts = {} if ref($opts) ne 'HASH';
    my $warn = sub {
        my ($message, $context) = @_;
        return if $opts->{suppress_warnings};
        add_warning('schedule', $message, $context);
    };
    my $stat = sub {
        my ($key, $count) = @_;
        return if $opts->{skip_stats};
        increment_stat($key, $count);
    };
    my $data = $obj->{data};
    return [] if !defined $data;

    my $name = exported_schedule_name($data->{name} // $obj->{ref});
    return [] if $name eq '';
    my $description = escape_html($data->{comment} // '');
    my $class_type = ($obj->{class} // '') . '/' . ($obj->{type} // '');

    if ($class_type eq 'time/recurring') {
        my $start_time = normalize_schedule_time_slot($data->{start_time});
        my $stop_time = normalize_schedule_time_slot($data->{end_time});
        my $days = normalize_schedule_weekday_labels($data->{weekdays} // $data->{weekday});

        if ($start_time eq '' || $stop_time eq '' || !@$days) {
            $warn->('Skipping recurring schedule because required fields are not convertible for SFOS', {
                schedule => $data->{name} // $obj->{ref},
                start_time => $data->{start_time} // '',
                end_time => $data->{end_time} // '',
                weekdays => join(',', @{ ensure_arrayref($data->{weekdays} // $data->{weekday}) }),
            });
            $stat->('schedule.recurring.skipped.invalid');
            return [];
        }
        if ($start_time eq $stop_time) {
            $warn->('Skipping recurring schedule because StartTime and StopTime collapse to the same value after normalization', {
                schedule => $data->{name} // $obj->{ref},
                start_time => $start_time,
            });
            $stat->('schedule.recurring.skipped.equal_time');
            return [];
        }

        my @details;
        if ($start_time gt $stop_time) {
            my $source_days = expand_schedule_weekday_labels($days);
            my $next_days = shift_schedule_weekday_labels_forward($source_days);
            if (!@$source_days || !@$next_days || @$source_days != @$next_days) {
                $warn->('Skipping recurring schedule because overnight weekday shift could not be resolved deterministically', {
                    schedule => $data->{name} // $obj->{ref},
                    weekdays => join(',', @$days),
                });
                $stat->('schedule.recurring.skipped.invalid');
                return [];
            }

            for my $idx (0 .. $#$source_days) {
                if ($start_time ne '23:59') {
                    push @details, { days => $source_days->[$idx], start_time => $start_time, stop_time => '23:59' };
                }
                if ($stop_time ne '00:00') {
                    push @details, { days => $next_days->[$idx], start_time => '00:00', stop_time => $stop_time };
                }
            }

            if (!@details) {
                $warn->('Skipping recurring schedule because overnight normalization produced no SFOS-valid time slots', {
                    schedule => $data->{name} // $obj->{ref},
                    start_time => $start_time,
                    stop_time => $stop_time,
                });
                $stat->('schedule.recurring.skipped.invalid');
                return [];
            }

            $warn->('Recurring schedule spans midnight; split into two SFOS-valid ScheduleDetail entries', {
                schedule => $data->{name} // $obj->{ref},
                start_time => $start_time,
                stop_time => $stop_time,
            });
            $stat->('schedule.recurring.overnight_split');
        } else {
            @details = map { { days => $_, start_time => $start_time, stop_time => $stop_time } } @$days;
        }

        $stat->('schedule.recurring');
        return {
            name => $name,
            description => $description,
            schedule_type => 'Recurring',
            is_recurring => 1,
            details => \@details,
        };
    }

    my $start_date = normalize_schedule_date($data->{start_date});
    my $end_date = normalize_schedule_date($data->{end_date});
    if ($start_date eq '' || $end_date eq '') {
        $warn->('Skipping one-time schedule because StartDate or EndDate is invalid for SFOS import', {
            schedule => $data->{name} // $obj->{ref},
            start_date => $data->{start_date} // '',
            end_date => $data->{end_date} // '',
        });
        $stat->('schedule.onetime.skipped.invalid');
        return [];
    }
    if ($start_date gt $end_date) {
        ($start_date, $end_date) = ($end_date, $start_date);
        $warn->('One-time schedule had inverted date range; dates were swapped for deterministic import', {
            schedule => $data->{name} // $obj->{ref},
            start_date => $start_date,
            end_date => $end_date,
        });
    }

    $stat->('schedule.onetime');
    return {
        name => $name,
        description => $description,
        schedule_type => 'OneTime',
        is_onetime => 1,
        start_date => $start_date,
        end_date => $end_date,
    };
}

sub parse_time_settings {
    my ($backup) = @_;
    my $ntp = $backup->{main}->{ntp};
    return [] if !defined $ntp || !exists $ntp->{status};

    my @servers;
    for my $server (@{ensure_arrayref($ntp->{servers})}) {

        if (defined $server && $server =~ /^REF_/) {
            my $obj = get_ref($backup, $server);
            if ($obj && $obj->{data}) {
                if ($obj->{data}->{hostname}) {
                    push @servers, $obj->{data}->{hostname};
                } elsif ($obj->{data}->{address}) {
                    push @servers, $obj->{data}->{address};
                }
                next;
            }
        }
        push @servers, $server if defined $server && $server ne '';
    }
    return [] if !@servers;

    increment_stat('time.ntp');
    return {
        use_custom_servers => (@servers ? 1 : 0),
        custom_servers => [ map { { server => $_ } } @servers ],
        sync_mode => (@servers ? 'Enable' : 'Disable'),
    };
}

sub parse_ntp_server {
    my ($backup) = @_;
    my $ntp = $backup->{main}->{ntp};
    return [] if !defined $ntp || !exists $ntp->{status};

    my $enabled = is_true($ntp->{status});
    return [] if !$enabled;

    my @source_names = @{ refs_to_network_names($backup, $ntp->{allowed_networks}) };
    return [] if !@source_names;

    my @ntp_server_names;
    for my $server_ref (@{ensure_arrayref($ntp->{servers})}) {
        next if !defined $server_ref || $server_ref eq '';
        next if $server_ref !~ /^REF_/;
        my $server_name = ref_to_preferred_network_name($backup, $server_ref);
        push @ntp_server_names, $server_name if $server_name ne '';
    }
    my %seen_server;
    @ntp_server_names = grep { !$seen_server{$_}++ } @ntp_server_names;
    return [] if !@ntp_server_names;
    my @nat_compatible_server_names = grep { $_ =~ /^(?:Host IP:|Host IPv6:|Network:|Network IPv6:|Range:|Range IPv6:)/ } @ntp_server_names;
    my $destination_name = @nat_compatible_server_names ? $nat_compatible_server_names[0] : $ntp_server_names[0];
    if (!@nat_compatible_server_names) {
        add_warning('ntp-server', 'NTP server destination resolved to non-NAT-compatible object type; keeping best-effort destination', {
            destination => $destination_name,
        });
    }

    my %seen_source;
    @source_names = grep { !$seen_source{$_}++ } @source_names;

    increment_stat('ntp.server_rule');
    return {
        has_ntp => 1,
        nat_rule_name => 'NTP Server',
        nat_description => '',
        nat_status => 'Enable',
        nat_position => 'Top',
        nat_linked_firewall => 'None',
        nat_source_networks => [ map { { name => $_ } } @source_names ],
        nat_translated_dest => $destination_name,
        nat_original_service => 'NTP',
        nat_translated_service => 'Original',
        nat_translated_source => 'MASQ',
        nat_method => '0',
        nat_health_check => 'Disable',
        rule_name => 'NTP Server',
        description => 'NTP Server Access',
        status => 'Enable',
        position => 'Top',
        action => 'Accept',
        logtraffic => 'Enable',
        services => [{ name => 'NTP' }],
        sources => [ map { { name => $_ } } @source_names ],
        destinations => [{ name => $destination_name }],
    };
}

sub dos_flood_value {
    my ($profile, $field, $default) = @_;
    return $default if ref($profile) ne 'HASH';
    my $value = $profile->{$field};
    return $default if !defined $value || $value eq '';
    return $value;
}

sub dos_flood_apply_flags {
    my ($profile) = @_;
    return ('Disable', 'Disable') if !is_true($profile->{status});

    my $mode = lc($profile->{mode} // 'src-dst');
    return ('Enable', 'Disable') if $mode eq 'src';
    return ('Disable', 'Enable') if $mode eq 'dst';
    return ('Enable', 'Enable');
}

sub parse_dos_settings {
    my ($backup) = @_;
    my $main = $backup->{main};
    return [] if ref($main) ne 'HASH';

    my $packetfilter = $backup->{main}->{packetfilter};
    my $ips = $backup->{main}->{ips};

    # UTM snapshots commonly store this at main->flood_protection; keep older path fallbacks for safety.
    my $flood = $main->{flood_protection};
    $flood = $packetfilter->{flood_protection}
        if (!defined $flood || ref($flood) ne 'HASH') && ref($packetfilter) eq 'HASH';
    $flood = $ips->{flood_protection}
        if (!defined $flood || ref($flood) ne 'HASH') && ref($ips) eq 'HASH';
    return [] if !defined $flood || ref($flood) ne 'HASH';

    my $syn = (ref($flood->{syn}) eq 'HASH') ? $flood->{syn} : {};
    my $udp = (ref($flood->{udp}) eq 'HASH') ? $flood->{udp} : {};
    my $icmp = (ref($flood->{icmp}) eq 'HASH') ? $flood->{icmp} : {};
    return [] if !is_true($syn->{status}) && !is_true($udp->{status}) && !is_true($icmp->{status});

    my ($syn_src_apply, $syn_dst_apply) = dos_flood_apply_flags($syn);
    my ($udp_src_apply, $udp_dst_apply) = dos_flood_apply_flags($udp);
    my ($icmp_src_apply, $icmp_dst_apply) = dos_flood_apply_flags($icmp);

    my $syn_src_packet = dos_flood_value($syn, 'src_rate', 100);
    my $syn_src_burst = dos_flood_value($syn, 'src_burst', 30);
    my $syn_dst_packet = dos_flood_value($syn, 'dst_rate', 200);
    my $syn_dst_burst = dos_flood_value($syn, 'dst_burst', 60);
    my $udp_src_packet = dos_flood_value($udp, 'src_rate', 200);
    my $udp_src_burst = dos_flood_value($udp, 'src_burst', 60);
    my $udp_dst_packet = dos_flood_value($udp, 'dst_rate', 300);
    my $udp_dst_burst = dos_flood_value($udp, 'dst_burst', 60);
    my $icmp_src_packet = dos_flood_value($icmp, 'src_rate', 10);
    my $icmp_src_burst = dos_flood_value($icmp, 'src_burst', 2);
    my $icmp_dst_packet = dos_flood_value($icmp, 'dst_rate', 20);
    my $icmp_dst_burst = dos_flood_value($icmp, 'dst_burst', 2);

    my @unsupported_log_protocols;
    for my $proto (qw(syn udp icmp)) {
        my $profile = $flood->{$proto};
        next if ref($profile) ne 'HASH' || !is_true($profile->{status});
        my $log_mode = lc($profile->{log} // 'off');
        next if $log_mode eq 'off';
        push @unsupported_log_protocols, $proto;
    }
    if (@unsupported_log_protocols) {
        add_warning('dos.settings', 'UTM flood logging settings are not mapped to SFOS DoSSettings and were ignored', {
            protocols => \@unsupported_log_protocols,
        });
    }

    increment_stat('dos.settings');
    return {
        enabled => 'Enable',
        syn_src_packet => $syn_src_packet,
        syn_src_burst => $syn_src_burst,
        syn_src_apply => $syn_src_apply,
        syn_dst_packet => $syn_dst_packet,
        syn_dst_burst => $syn_dst_burst,
        syn_dst_apply => $syn_dst_apply,
        udp_src_packet => $udp_src_packet,
        udp_src_burst => $udp_src_burst,
        udp_src_apply => $udp_src_apply,
        udp_dst_packet => $udp_dst_packet,
        udp_dst_burst => $udp_dst_burst,
        udp_dst_apply => $udp_dst_apply,
        tcp_src_packet => $syn_src_packet,
        tcp_src_burst => $syn_src_burst,
        tcp_src_apply => $syn_src_apply,
        tcp_dst_packet => $syn_dst_packet,
        tcp_dst_burst => $syn_dst_burst,
        tcp_dst_apply => $syn_dst_apply,
        icmp_src_packet => $icmp_src_packet,
        icmp_src_burst => $icmp_src_burst,
        icmp_src_apply => $icmp_src_apply,
        icmp_dst_packet => $icmp_dst_packet,
        icmp_dst_burst => $icmp_dst_burst,
        icmp_dst_apply => $icmp_dst_apply,
    };
}

sub dos_bypass_literals_for_ref {
    my ($backup, $ref, $direction, $visited) = @_;
    return () if !defined $ref || $ref eq '';
    $visited //= {};
    return () if $visited->{$ref}++;

    my $obj = get_ref($backup, $ref);
    return () if !$obj || ref($obj->{data}) ne 'HASH';

    if (($obj->{class} // '') eq 'network' && ($obj->{type} // '') eq 'group') {
        my @ret;
        for my $member_ref (@{ ensure_arrayref($obj->{data}->{members}) }) {
            push @ret, dos_bypass_literals_for_ref($backup, $member_ref, $direction, $visited);
        }
        return @ret;
    }

    return ('*') if is_any_network($obj);

    my @ret;
    my $parsed = parse_one_host($backup, $obj);
    for my $entry (@{ ensure_arrayref($parsed) }) {
        next if ref($entry) ne 'HASH';
        next if ($entry->{family} // '') ne 'IPv4';

        my $address = $entry->{address} // '';
        if (($entry->{iphost} // 0) && is_valid_ipv4_literal($address)) {
            push @ret, $address;
            next;
        }

        if (($entry->{network} // 0) && is_valid_ipv4_literal($address)) {
            my $subnet = $entry->{subnet} // '';
            if ($subnet ne '' && $subnet =~ /^\d+$/ && $subnet >= 0 && $subnet <= 32) {
                push @ret, "$address/$subnet";
            } elsif ($subnet ne '' && is_valid_ipv4_literal($subnet)) {
                my $prefix = ipv4_prefixlen_from_netmask($subnet);
                if ($prefix ne '') {
                    push @ret, "$address/$prefix";
                } else {
                    push @ret, $address;
                }
            } else {
                push @ret, $address;
            }
            next;
        }
    }

    if (!@ret) {
        add_warning('dos.bypass', 'Skipping DoS bypass network reference because no SFOS-compatible IPv4 literal could be derived', {
            direction => $direction,
            reference => $ref,
            source_type => (($obj->{class} // '') . '/' . ($obj->{type} // '')),
        });
    }
    return @ret;
}

sub dos_bypass_literals_from_refs {
    my ($backup, $refs, $direction) = @_;
    my @ret;
    my %seen_literal;
    my %visited;

    for my $ref (@{ ensure_arrayref($refs) }) {
        for my $literal (dos_bypass_literals_for_ref($backup, $ref, $direction, \%visited)) {
            return ['*'] if $literal eq '*';
            next if $seen_literal{$literal}++;
            push @ret, $literal;
        }
    }
    return \@ret;
}

sub parse_dos_bypass_rule {
    my ($backup, $obj) = @_;
    my $data = $obj->{data};
    return [] if !defined $data;
    my @skiplist = @{ensure_arrayref($data->{skiplist})};
    my %flood_skip = map { $_ => 1 } qw(tcp_flood udp_flood icmp_flood);
    return [] if !grep { $flood_skip{$_} } @skiplist;

    my @sources = @{ dos_bypass_literals_from_refs($backup, $data->{source_networks}, 'source') };
    my @destinations = @{ dos_bypass_literals_from_refs($backup, $data->{destination_networks}, 'destination') };
    @sources = ('*') if !@sources;
    @destinations = ('*') if !@destinations;

    my @rules;
    for my $src (@sources) {
        for my $dst (@destinations) {
            push @rules, {
                name => escape_trunc("Flood bypass $src to $dst"),
                ipfamily => 'IPv4',
                source => $src,
                destination => $dst,
                protocol => 'AllProtocol',
                source_port => '*',
                destination_port => '*',
            };
        }
    }
    increment_stat('dos.bypass', scalar @rules);
    return \@rules;
}

sub build_nat_auto_firewall_rule {
    my (%args) = @_;
    return {
        enabled => 1,
        rule_name => $args{rule_name},
        description => $args{description},
        status => $args{status},
        action => 'Accept',
        logtraffic => ($LOG_FIREWALL ? 'Enable' : 'Disable'),
        position => 'Bottom',
        services => [ map { { name => $_ } } @{ensure_arrayref($args{services})} ],
        sources => [ map { { name => $_ } } @{ensure_arrayref($args{sources})} ],
        destinations => [ map { { name => $_ } } @{ensure_arrayref($args{destinations})} ],
        policy_type => 'Network',
    };
}

sub normalize_nat_outbound_interface_refs {
    my ($data) = @_;
    my @refs;
    for my $key (qw(source_nat_interface source_nat_interfaces outbound_interface outbound_interfaces outboundinterface)) {
        next if !defined $data->{$key};
        push @refs, @{ ensure_arrayref($data->{$key}) };
    }
    my %seen;
    @refs = grep { defined $_ && $_ ne '' && $_ ne '-1' && !$seen{$_}++ } @refs;
    return \@refs;
}

sub resolve_nat_outbound_interface_names {
    my ($backup, $rule_name, $refs) = @_;
    my @names;
    for my $if_ref (@{ ensure_arrayref($refs) }) {
        my $if_ctx = resolve_dhcp_interface_context($backup, $if_ref);
        my $resolved_name = $if_ctx->{interface_name} // '';
        my $if_obj = get_ref($backup, $if_ref);
        my $source_name = $resolved_name;
        if ($source_name eq '' && $if_obj && $if_obj->{data}) {
            $source_name = $if_obj->{data}->{name} // '';
        }

        my $mapped_name = map_utm_interface_name_to_sfos($source_name);
        if ($mapped_name ne '') {
            push @names, $mapped_name;
            if ($source_name ne '' && lc($source_name) ne lc($mapped_name)) {
                add_warning('nat', 'Mapped outbound NAT interface to SFOS-compatible placeholder', {
                    rule => $rule_name,
                    interface_ref => $if_ref,
                    source_interface => $source_name,
                    mapped_interface => $mapped_name,
                });
                increment_stat('nat.interface.outbound.mapped');
            }
            next;
        }

        my $fallback_name = map_utm_interface_name_to_sfos($INTERFACE_ROUTE_NAME);
        if ($source_name ne '' && $fallback_name ne '') {
            push @names, $fallback_name;
            add_warning('nat', 'Outbound NAT interface is not SFOS-compatible; using interface default override (-I)', {
                rule => $rule_name,
                interface_ref => $if_ref,
                source_interface => $source_name,
                fallback_interface => $fallback_name,
            });
            increment_stat('nat.interface.outbound.defaulted');
            next;
        }

        if ($source_name ne '') {
            add_warning('nat', 'Skipping outbound NAT interface because no SFOS-compatible PortN mapping was found', {
                rule => $rule_name,
                interface_ref => $if_ref,
                source_interface => $source_name,
            });
            increment_stat('nat.interface.outbound.skipped.unmapped');
        } else {
            add_warning('nat', 'Skipping outbound NAT interface because reference could not be resolved', {
                rule => $rule_name,
                interface_ref => $if_ref,
            });
            increment_stat('nat.interface.outbound.skipped.unresolved');
        }
    }
    my %seen;
    @names = grep { !$seen{$_}++ } grep { $_ ne '' } @names;
    return \@names;
}

sub parse_nat_rule {
    my ($backup, $obj) = @_;
    my $data = $obj->{data};
    return [] if !defined $data;

    my $rule_name = escape_trunc($data->{name} // $obj->{ref});
    my @sources = @{ ref_to_network_names($backup, $data->{source}) };
    my @destinations = @{ ref_to_network_names($backup, $data->{destination}) };
    my $service = ref_to_service_name($backup, $data->{service});

    my $translated_source = 'Original';
    my $translated_destination = 'Original';
    my $translated_service = 'Original';
    my $mode = $data->{mode} // '';
    my $type = $obj->{type} // '';

    if ($type eq 'nat') {
        if ($mode eq 'snat' || $mode eq 'full') {
            my $snat = ref_to_preferred_network_name($backup, $data->{source_nat_address});
            $translated_source = ($snat ne '' ? $snat : 'MASQ');
        }
        if ($mode eq 'dnat' || $mode eq 'full') {
            my $dnat = ref_to_preferred_network_name($backup, $data->{destination_nat_address});
            $translated_destination = ($dnat ne '' ? $dnat : 'Original');
            my $dnsvc = ref_to_service_name($backup, $data->{destination_nat_service});
            $translated_service = $dnsvc if $dnsvc ne '';
        }
        if ($mode eq 'snat') {
            my $snsvc = ref_to_service_name($backup, $data->{source_nat_service});
            $translated_service = $snsvc if $snsvc ne '';
        }
    } elsif ($type eq '1to1nat') {
        my $map_to = ref_to_preferred_network_name($backup, $data->{map_to});
        if (($mode // '') eq 'mapsrc') {
            $translated_source = ($map_to ne '' ? $map_to : 'Original');
        } else {
            $translated_destination = ($map_to ne '' ? $map_to : 'Original');
        }
    } elsif ($type eq 'masq') {
        $translated_source = 'MASQ';
        $service = 'Any';
    } elsif ($type eq 'loadbalance') {
        # packetfilter/loadbalance maps translated destination to a group
        my $dnat = ref_to_preferred_network_name($backup, $data->{group});
        $translated_destination = ($dnat ne '' ? $dnat : 'Original');
    }

    my %seen_sources;
    @sources = grep { !$seen_sources{$_}++ } grep { defined $_ && $_ ne '' } @sources;
    my %seen_destinations;
    @destinations = grep { !$seen_destinations{$_}++ } grep { defined $_ && $_ ne '' } @destinations;
    @sources = grep { $_ ne 'Any' && $_ ne 'Any IPv4' } @sources;
    @destinations = grep { $_ ne 'Any' && $_ ne 'Any IPv4' } @destinations;
    my @services = grep { $_ ne '' && $_ ne 'Any' && $_ ne 'Any IPv4' } ($service);

    my $linked_firewall = 'None';
    my $nat_auto_firewall;
    my %nat_auto_template = (
        nat_auto_enabled => 0,
        nat_auto_rule_name => '',
        nat_auto_description => '',
        nat_auto_status => '',
        nat_auto_position => '',
        nat_auto_action => '',
        nat_auto_logtraffic => '',
        nat_auto_services => [],
        nat_auto_sources => [],
        nat_auto_destinations => [],
    );
    if (is_true($data->{auto_pfrule})) {
        if ($NAT_STRATEGY eq 'compat') {
            my $fw_name = escape_trunc("NAT Auto FW: " . ($data->{name} // $obj->{ref}));
            $nat_auto_firewall = build_nat_auto_firewall_rule(
                rule_name => $fw_name,
                description => escape_html('Auto-generated from UTM NAT rule'),
                status => bool_to_enable_disable($data->{status}),
                sources => \@sources,
                destinations => \@destinations,
                services => \@services,
            );
            if ($nat_auto_firewall->{rule_name} && $nat_auto_firewall->{status} && $nat_auto_firewall->{action}) {
                $linked_firewall = $nat_auto_firewall->{rule_name};
                %nat_auto_template = (
                    nat_auto_enabled => 1,
                    nat_auto_rule_name => $nat_auto_firewall->{rule_name},
                    nat_auto_description => $nat_auto_firewall->{description},
                    nat_auto_status => $nat_auto_firewall->{status},
                    nat_auto_position => $nat_auto_firewall->{position},
                    nat_auto_action => $nat_auto_firewall->{action},
                    nat_auto_logtraffic => $nat_auto_firewall->{logtraffic},
                    nat_auto_services => $nat_auto_firewall->{services},
                    nat_auto_sources => $nat_auto_firewall->{sources},
                    nat_auto_destinations => $nat_auto_firewall->{destinations},
                );
                increment_stat('nat.auto_firewall');
            } else {
                add_warning('nat', 'compat NAT auto firewall rule generation failed validation; falling back to no linked firewall rule', {
                    rule => $data->{name} // $obj->{ref},
                });
            }
        } else {
            add_warning('nat', 'auto_pfrule is enabled but NAT strategy is safe; linked firewall rule not generated', {
                rule => $data->{name} // $obj->{ref},
            });
        }
    }

    my $is_loadbalance = ($type eq 'loadbalance') ? 1 : 0;
    my $lbmethod = 'Round_robin'; # fallback
    if ($is_loadbalance) {
        my %method_map = (
            'lb_round_robin' => 'Round_robin',
            'lb_sticky' => 'StickyIP',
            # Any other UTM methods map here if known
        );
        my $m = $data->{lb_method} // '';
        $lbmethod = $method_map{$m} if exists $method_map{$m};
    }
    my $nat_method = $is_loadbalance ? $lbmethod : '0';
    my $health_check = $is_loadbalance ? 'Enable' : 'Disable';
    my $outbound_interface_refs = normalize_nat_outbound_interface_refs($data);
    my $outbound_interface_names = resolve_nat_outbound_interface_names($backup, $rule_name, $outbound_interface_refs);

    if ((defined $data->{position} && $data->{position} ne '') || (defined $data->{after} && $data->{after} ne '')) {
        add_warning('nat', 'Legacy relative NAT ordering is not mapped; using deterministic Bottom position', {
            rule => $rule_name,
            position => $data->{position} // '',
            after => $data->{after} // '',
        });
        increment_stat('nat.rule.position.defaulted');
    }

    increment_stat('nat.rule');
    return {
        enabled => 1,
        name => $rule_name,
        description => escape_html($data->{comment} // ''),
        status => bool_to_enable_disable($data->{status}),
        linked_firewall => $linked_firewall,
        sources => [ map { { name => $_ } } @sources ],
        destinations => [ map { { name => $_ } } @destinations ],
        services => [ map { { name => $_ } } @services ],
        outbound_interfaces => [ map { { name => $_ } } @$outbound_interface_names ],
        translated_source => $translated_source,
        translated_destination => $translated_destination,
        translated_service => $translated_service,
        is_loadbalance => $is_loadbalance,
        lbmethod => $lbmethod,
        nat_method => $nat_method,
        health_check => $health_check,
        %nat_auto_template,
    };
}

sub build_dhcp_server_from_hash {
    my ($backup, $server, $idx, $server_ref) = @_;
    $server_ref //= '';
    my $name = $server->{name} // $server->{dhcpname} // ("UTM DHCP Server " . ($idx + 1));
    my $relay_mode = is_true($server->{relay_mode}) ? 1 : 0;
    my $interface = '';
    my $interface_ref = $server->{interface}
        // $server->{selectlocaladdress}
        // $server->{select_local_address}
        // $server->{localaddress}
        // '';
    my $interface_context = resolve_dhcp_interface_context($backup, $interface_ref);
    my $address_ref = $server->{address}
        // $server->{address_ref}
        // '';
    if ($address_ref ne '' && $address_ref ne '-1') {
        my $address_context = resolve_dhcp_interface_context($backup, $address_ref);
        if (ref($address_context) eq 'HASH') {
            for my $key (qw(interface_ip subnet_mask gateway)) {
                my $candidate = $address_context->{$key} // '';
                $interface_context->{$key} = $candidate if $candidate ne '';
            }
        }
    }
    if ($interface_ref ne '' && $interface_ref ne '-1') {
        $interface = ref_to_object_name($backup, $interface_ref);
        my $context_interface_name = $interface_context->{interface_name} // '';
        if (
            $interface eq ''
            || $interface =~ /^\d{1,3}(?:\.\d{1,3}){3}\/\d+$/
        ) {
            $interface = $context_interface_name if $context_interface_name ne '';
        }
        my $mapped_interface = map_utm_interface_name_to_sfos($interface);
        if ($mapped_interface ne '') {
            if ($interface ne '' && lc($interface) ne lc($mapped_interface)) {
                add_warning('dhcp-server', 'Mapped DHCP interface to SFOS-compatible placeholder', {
                    server => $name,
                    source_interface => $interface,
                    interface_ref => $interface_ref,
                    mapped_interface => $mapped_interface,
                });
                increment_stat('dhcp.server.interface.mapped');
            }
            $interface = $mapped_interface;
        }
        if (!is_sfos_gateway_interface_name($interface)) {
            my $fallback_interface = map_utm_interface_name_to_sfos($DEFAULT_DHCP_INTERFACE_NAME);
            if ($fallback_interface ne '') {
                add_warning('dhcp-server', 'DHCP interface name is not SFOS-compatible; using DHCP default interface override (-D)', {
                    server => $name,
                    source_interface => $interface,
                    interface_ref => $interface_ref,
                    fallback_interface => $fallback_interface,
                });
                increment_stat('dhcp.server.interface.defaulted');
                $interface = $fallback_interface;
            }
        }
        if ($interface eq '' && is_sfos_gateway_interface_name($interface_ref)) {
            $interface = $interface_ref;
        }
    }

    my @lease_ranges;
    if (($server->{range_start} // '') ne '' && ($server->{range_end} // '') ne '') {
        push @lease_ranges, $server->{range_start} . '-' . $server->{range_end};
    }
    if (!@lease_ranges) {
        for my $range (@{ensure_arrayref($server->{lease_ranges} // $server->{leaseranges})}) {
            next if !defined $range || $range eq '';
            push @lease_ranges, $range;
        }
    }
    if (!@lease_ranges && ($server->{start_ip} // '') ne '' && ($server->{end_ip} // '') ne '') {
        push @lease_ranges, $server->{start_ip} . '-' . $server->{end_ip};
    }

    my @leases;
    my %seen_static_hostnames;
    for my $mapping_ref (@{ensure_arrayref($server->{mappings})}) {
        my $host = get_ref($backup, $mapping_ref);
        next if !$host || !$host->{data};
        my $ip = $host->{data}->{address} // '';
        my $host_name = $host->{data}->{name} // $mapping_ref;
        my @macs = @{ensure_arrayref($host->{data}->{macs})};
        if ($ip eq '' || !@macs) {
            add_warning('dhcp-static', 'Skipping DHCP static lease mapping without both IPv4 and MAC', {
                host_ref => $mapping_ref,
                server => $name,
            });
            next;
        }

        my $hostname_projection = normalize_dhcp_static_hostname_for_sfos($host_name, $ip, $mapping_ref);
        my $projected_hostname = $hostname_projection->{hostname} // '';
        if ($projected_hostname eq '') {
            add_warning('dhcp-static', 'Skipping DHCP static lease mapping because hostname is not SFOS dhcpHostname compatible after normalization', {
                host_ref => $mapping_ref,
                server => $name,
                ip_address => $ip,
                original_hostname => $host_name,
                reason => $hostname_projection->{reason} // '',
            });
            increment_stat('dhcp.static.hostname.skipped');
            next;
        }
        if ($hostname_projection->{changed}) {
            add_warning('dhcp-static', 'Normalized DHCP static lease hostname for SFOS dhcpHostname validator compatibility', {
                host_ref => $mapping_ref,
                server => $name,
                ip_address => $ip,
                original_hostname => $host_name,
                sanitized_hostname => $projected_hostname,
                normalization_source => $hostname_projection->{source} // '',
            });
            increment_stat('dhcp.static.hostname.normalized');
        }

        my $unique_projection = project_unique_dhcp_static_hostname_for_sfos(
            hostname => $projected_hostname,
            ip_address => $ip,
            host_ref => $mapping_ref,
            seen_hostnames => \%seen_static_hostnames,
        );
        my $unique_hostname = $unique_projection->{hostname} // '';
        if ($unique_hostname eq '') {
            add_warning('dhcp-static', 'Skipping DHCP static lease mapping because a unique SFOS-compatible hostname could not be derived', {
                host_ref => $mapping_ref,
                server => $name,
                ip_address => $ip,
                original_hostname => $host_name,
                projected_hostname => $projected_hostname,
                reason => $unique_projection->{reason} // '',
            });
            increment_stat('dhcp.static.hostname.skipped');
            next;
        }
        if ($unique_projection->{collision}) {
            add_warning('dhcp-static', 'Resolved DHCP static lease hostname collision after normalization for SFOS import safety', {
                host_ref => $mapping_ref,
                server => $name,
                ip_address => $ip,
                original_hostname => $host_name,
                collision_hostname => $projected_hostname,
                resolved_hostname => $unique_hostname,
                resolution_source => $unique_projection->{source} // '',
            });
            increment_stat('dhcp.static.hostname.collision_resolved');
        }

        push @leases, {
            hostname => escape_trunc($unique_hostname),
            mac_address => $macs[0],
            ip_address => $ip,
        };
    }
    @leases = @{ enforce_dhcp_static_lease_tuple_consistency(
        server_name => $name,
        leases => \@leases,
    ) };
    my $option_projection = collect_dhcp_server_option_projection(
        backup => $backup,
        server_name => $name,
        server_ref => $server_ref,
    );
    my $boot_server = escape_html($server->{boot_server} // $server->{bootserver} // ($option_projection->{boot_server} // ''));
    my $boot_file = escape_html($server->{boot_file} // $server->{bootfile} // ($option_projection->{boot_file} // ''));
    my @dhcp_options = @{ensure_arrayref($option_projection->{dhcp_options})};

    my $server_subnet_mask = normalize_dhcp_subnet_mask($server->{subnet_mask} // $server->{subnetmask} // $server->{netmask} // '');
    my $subnet_mask = '';
    if ($relay_mode) {
        $subnet_mask = $server_subnet_mask;
        $subnet_mask = normalize_dhcp_subnet_mask($interface_context->{subnet_mask} // '') if $subnet_mask eq '';
    } else {
        $subnet_mask = normalize_dhcp_subnet_mask($interface_context->{subnet_mask} // '');
        $subnet_mask = $server_subnet_mask if $subnet_mask eq '';
    }
    my $domain_name = $server->{domain_name} // $server->{domainname} // $server->{domain} // '';
    my $lease_time_seconds = $server->{lease_time};
    my $default_lease_time = $server->{default_lease_time} // $server->{defaultleasetime} // '';
    my $max_lease_time = $server->{max_lease_time} // $server->{maxleasetime} // '';
    if ($default_lease_time eq '' && $max_lease_time eq '' && defined $lease_time_seconds && $lease_time_seconds =~ /^\d+$/) {
        my $lease_time_minutes = int(($lease_time_seconds + 59) / 60);
        $lease_time_minutes = 1 if $lease_time_minutes < 1;
        $default_lease_time = $lease_time_minutes;
        $max_lease_time = $lease_time_minutes;
    }
    my $gateway = normalize_ipv4_or_empty(ipv4_from_optional_prefix($server->{gateway} // $server->{default_gateway} // ''));
    my $primary_dns = normalize_ipv4_or_empty($server->{primary_dns} // $server->{primarydns} // $server->{dns1} // '');
    my $secondary_dns = normalize_ipv4_or_empty($server->{secondary_dns} // $server->{secondarydns} // $server->{dns2} // '');
    my $wins_node_type = defined $server->{wins_node_type} ? $server->{wins_node_type} : '';
    my $wins = normalize_ipv4_or_empty($server->{wins} // '');
    my $primary_wins = '';
    if ($wins ne '' && $wins ne '0.0.0.0' && $wins_node_type =~ /^\d+$/ && $wins_node_type > 1) {
        $primary_wins = $wins;
    }
    if ($wins_node_type ne '' && $wins_node_type ne '1') {
        add_warning('dhcp-server', 'UTM WINS node type has no direct SFOS DHCPServer equivalent and is omitted', {
            server => $name,
            wins_node_type => $wins_node_type,
        });
        increment_stat('dhcp.server.wins_node_type.omitted');
    }
    if (is_true($server->{deny_unknown})) {
        add_warning('dhcp-server', 'UTM deny_unknown has no direct SFOS DHCPServer equivalent and is omitted', {
            server => $name,
        });
        increment_stat('dhcp.server.deny_unknown.omitted');
    }
    if (is_true($server->{proxy_autoconfig})) {
        add_warning('dhcp-server', 'UTM proxy_autoconfig has no direct SFOS DHCPServer equivalent and is omitted', {
            server => $name,
        });
        increment_stat('dhcp.server.proxy_autoconfig.omitted');
    }

    $default_lease_time = 1440 if $default_lease_time !~ /^\d+$/ || $default_lease_time < 1 || $default_lease_time > 43200;
    $max_lease_time = $default_lease_time if $max_lease_time !~ /^\d+$/ || $max_lease_time < 1 || $max_lease_time > 43200;
    $max_lease_time = $default_lease_time if $max_lease_time < $default_lease_time;

    my $use_interface_ip_as_gateway = 'ANY';
    if (!$relay_mode) {
        if ($gateway eq '') {
            $gateway = $interface_context->{gateway} // '';
        }
        if ($gateway eq '') {
            $gateway = $interface_context->{interface_ip} // '';
        }
        if ($gateway eq '' && $interface_ref ne '' && $interface_ref ne '-1') {
            $use_interface_ip_as_gateway = 'UseInterfaceIPAsGateway';
        }
    }

    my @reserved_ips_for_leases = map { $_->{ip_address} } @leases;
    push @reserved_ips_for_leases, ($interface_context->{interface_ip} // '');
    push @reserved_ips_for_leases, $gateway if $gateway ne '';
    my @normalized_lease_ranges;
    my %seen_lease_ranges;
    for my $range (@lease_ranges) {
        my $split_ranges = split_ipv4_lease_range_for_reserved_ips(
            server_name => $name,
            range => $range,
            reserved_ips => \@reserved_ips_for_leases,
        );
        for my $normalized_range (@{ensure_arrayref($split_ranges)}) {
            next if !defined $normalized_range || $normalized_range eq '';
            next if $seen_lease_ranges{$normalized_range}++;
            push @normalized_lease_ranges, $normalized_range;
        }
    }
    @lease_ranges = @normalized_lease_ranges;
    my $interface_subnet_bounds;
    if (!$relay_mode) {
        $interface_subnet_bounds = ipv4_subnet_bounds_from_ip_and_mask(
            interface_ip => $interface_context->{interface_ip} // '',
            subnet_mask => $subnet_mask,
        );
        my $out_of_subnet_lease_ranges = warn_dhcp_lease_ranges_outside_interface_subnet(
            server_name => $name,
            interface_name => $interface,
            interface_ref => $interface_ref,
            interface_ip => $interface_context->{interface_ip} // '',
            subnet_mask => $subnet_mask,
            lease_ranges => \@lease_ranges,
        );
        if (@{$out_of_subnet_lease_ranges}) {
            add_warning('dhcp-server', 'Exporting DHCP server as disabled because lease ranges fall outside the resolved interface subnet', {
                server => $name,
                interface => $interface,
                interface_ref => $interface_ref,
                interface_ip => $interface_context->{interface_ip} // '',
                subnet_mask => $subnet_mask,
                offending_ranges => join(',', @{$out_of_subnet_lease_ranges}),
            });
            increment_stat('dhcp.server.subnet_mismatch');
        }

        if (
            $gateway ne ''
            && $use_interface_ip_as_gateway ne 'UseInterfaceIPAsGateway'
            && $interface_subnet_bounds
            && !ipv4_is_within_subnet_bounds(ip => $gateway, subnet_bounds => $interface_subnet_bounds)
        ) {
            add_warning('dhcp-server', 'Exporting DHCP server as disabled because Gateway is outside the resolved interface subnet', {
                server => $name,
                interface => $interface,
                interface_ref => $interface_ref,
                gateway => $gateway,
                interface_subnet => $interface_subnet_bounds->{network_ip} . '-' . $interface_subnet_bounds->{broadcast_ip},
            });
            increment_stat('dhcp.server.gateway_subnet_mismatch');
        }

        if ($interface_subnet_bounds && @leases) {
            my @out_of_subnet_static_ips = ();
            for my $lease (@leases) {
                my $static_ip = normalize_ipv4_or_empty($lease->{ip_address} // '');
                next if $static_ip eq '';
                next if ipv4_is_within_subnet_bounds(ip => $static_ip, subnet_bounds => $interface_subnet_bounds);
                push @out_of_subnet_static_ips, $static_ip;
            }
            if (@out_of_subnet_static_ips) {
                add_warning('dhcp-server', 'Exporting DHCP server as disabled because static lease IPs are outside the resolved interface subnet', {
                    server => $name,
                    interface => $interface,
                    interface_ref => $interface_ref,
                    static_ips => join(',', @out_of_subnet_static_ips),
                    interface_subnet => $interface_subnet_bounds->{network_ip} . '-' . $interface_subnet_bounds->{broadcast_ip},
                });
                increment_stat('dhcp.server.static_ip_subnet_mismatch');
            }
        }
    }

    my @missing_fields;
    push @missing_fields, 'Interface' if $interface eq '';
    push @missing_fields, 'SubnetMask' if $subnet_mask eq '';
    push @missing_fields, 'Gateway' if $gateway eq '' && $use_interface_ip_as_gateway ne 'UseInterfaceIPAsGateway';
    push @missing_fields, 'LeaseRangeOrStaticLease' if !@lease_ranges && !@leases;
    if (@missing_fields) {
        add_warning('dhcp-server', 'Skipping DHCP server with incomplete required fields for SFOS import', {
            server => $name,
            missing => join(',', @missing_fields),
        });
        increment_stat('dhcp.server.skipped');
        return undef;
    }

    # SFOS import accepts broader DHCP payloads when server status is disabled.
    my $status = 0;
    my $use_appliance_dns = ($primary_dns eq '' && $secondary_dns eq '') ? 'Enable' : 'Disable';

    return {
        enabled => 1,
        name => escape_trunc($name),
        status => $status,
        interface => $interface,
        lease_ranges => [ map { { range => $_ } } @lease_ranges ],
        has_static_leases => scalar @leases,
        static_leases => \@leases,
        conflict_detection => bool_to_enable_disable($server->{conflict_detection} // $server->{chkConflictDetect}),
        lease_for_relay => bool_to_enable_disable(defined $server->{relay_mode} ? $server->{relay_mode} : ($server->{lease_for_relay} // $server->{chkleaseforrelay})),
        subnet_mask => $subnet_mask,
        domain_name => $domain_name,
        default_lease_time => $default_lease_time,
        max_lease_time => $max_lease_time,
        use_appliance_dns_settings => $use_appliance_dns,
        primary_dns => $primary_dns,
        secondary_dns => $secondary_dns,
        primary_wins => $primary_wins,
        secondary_wins => '',
        boot_server => $boot_server,
        boot_file => $boot_file,
        has_dhcp_options => scalar @dhcp_options,
        dhcp_options => \@dhcp_options,
        gateway => $gateway,
        use_interface_ip_as_gateway => $use_interface_ip_as_gateway,
    };
}

sub parse_dhcp_servers {
    my ($backup) = @_;
    my @ret;

    my @servers_from_main;
    my $main_server_node = $backup->{main}->{dhcp}->{server};
    if (ref($main_server_node) eq 'ARRAY') {
        @servers_from_main = @$main_server_node;
    } elsif (ref($main_server_node) eq 'HASH') {
        if (exists $main_server_node->{servers}) {
            @servers_from_main = @{ensure_arrayref($main_server_node->{servers})};
        } else {
            @servers_from_main = ($main_server_node);
        }
    }
    if (!@servers_from_main) {
        @servers_from_main = @{ensure_arrayref($backup->{main}->{dhcp}->{servers})};
    }

    for my $i (0 .. $#servers_from_main) {
        my $entry = $servers_from_main[$i];
        my $server_data;
        my $server_ref = '';
        if (ref($entry) eq 'HASH') {
            $server_data = $entry;
            $server_ref = $entry->{ref} // '';
        } elsif (!ref($entry) && defined $entry && $entry ne '') {
            my $entry_obj = get_ref($backup, $entry);
            $server_data = $entry_obj->{data} if $entry_obj && $entry_obj->{data};
            $server_ref = $entry if $entry_obj && $entry_obj->{data};
        }
        next if ref($server_data) ne 'HASH';
        my $server = build_dhcp_server_from_hash($backup, $server_data, $i, $server_ref);
        push @ret, $server if $server;
    }

    my @server_objects = grep { $_->{class} eq 'dhcp' && $_->{type} eq 'server' } values %{ $backup->{objects} };
    if (!@ret && @server_objects) {
        for my $i (0 .. $#server_objects) {
            my $server = build_dhcp_server_from_hash(
                $backup,
                $server_objects[$i]->{data},
                $i,
                $server_objects[$i]->{ref} // '',
            );
            push @ret, $server if $server;
        }
    }

    increment_stat('dhcp.server', scalar @ret);
    return \@ret;
}

sub parse_dhcp_servers_ipv6 {
    my ($backup) = @_;
    my @ret;

    my @server_objects = grep { $_->{class} eq 'dhcp' && $_->{type} eq 'server6' } values %{ $backup->{objects} };
    for my $i (0 .. $#server_objects) {
        my $server = build_dhcp_server_from_hash(
            $backup,
            $server_objects[$i]->{data},
            $i,
            $server_objects[$i]->{ref} // '',
        );
        if ($server) {
            foreach my $lease (@{$server->{static_leases} // []}) {
                $lease->{duid} = ''; # Empty DUID unless mapped
            }
            push @ret, $server;
        }
    }

    increment_stat('dhcp.server6', scalar @ret);
    return \@ret;
}

sub resolve_url_category_name {
    my ($obj) = @_;
    return '' if !$obj || !$obj->{data};
    return $obj->{data}->{name} if defined $obj->{data}->{name};
    return $obj->{data}->{id} if defined $obj->{data}->{id};
    return '';
}

sub normalize_webfilter_exception_regex {
    my ($value) = @_;
    my $regex = $value // '';
    $regex =~ s/^\s+|\s+$//g;
    return '' if $regex eq '';
    my $starts_anchored = ($regex =~ s/^\^//) ? 1 : 0;
    $regex =~ s{^https?\??:(?://|\\/\\/)}{}i;
    $regex =~ s{(?<!\\)/}{\\/}g;
    $regex = '.*' if $regex eq '*';
    if ($starts_anchored && $regex ne '' && substr($regex, 0, 1) ne '^') {
        $regex = '^' . $regex;
    }
    return $regex;
}

sub is_valid_sfos_urlregex {
    my ($url) = @_;
    if (!defined $url || $url eq '') {
        debug_validation_failure('is_valid_sfos_urlregex', $url, 'value is empty');
        return 0;
    }
    if (index($url, '^http://') == 0 || index($url, '^https://') == 0) {
        debug_validation_failure('is_valid_sfos_urlregex', $url, 'protocol-prefixed regex is not allowed');
        return 0;
    }
    if ($url !~ /^[\x20-\x7E]+$/) {
        debug_validation_failure('is_valid_sfos_urlregex', $url, 'contains non-printable or non-ASCII characters');
        return 0;
    }
    my $final = '"' . $url . '"';
    my $is_valid = eval { qr/$final/; 1; };
    if (!$is_valid) {
        my $error = $@ // 'unknown regex compilation error';
        chomp $error;
        debug_validation_failure('is_valid_sfos_urlregex', $url, "regex compilation failed: $error");
        return 0;
    }
    return $is_valid ? 1 : 0;
}

sub network_ref_to_cidr_list {
    my ($backup, $ref) = @_;
    my $obj = get_ref($backup, $ref);
    return [] if !$obj || !$obj->{data};
    my $data = $obj->{data};
    my @ret;

    if (defined $data->{members}) {
        for my $member (@{ensure_arrayref($data->{members})}) {
            push @ret, @{network_ref_to_cidr_list($backup, $member)};
        }
        return \@ret;
    }

    if (defined $data->{address} && $data->{address} ne '') {
        my $mask = 32;
        $mask = $data->{netmask} if defined $data->{netmask} && $data->{netmask} =~ /^\d+$/;
        push @ret, $data->{address} . '/' . $mask;
    }
    if (defined $data->{address6} && $data->{address6} ne '') {
        my $mask6 = 128;
        $mask6 = $data->{netmask6} if defined $data->{netmask6} && $data->{netmask6} =~ /^\d+$/;
        push @ret, $data->{address6} . '/' . $mask6;
    }
    return \@ret;
}

sub is_valid_ip_or_cidr {
    my ($value) = @_;
    if (!defined $value || $value eq '') {
        debug_validation_failure('is_valid_ip_or_cidr', $value, 'value is empty');
        return 0;
    }
    return 1 if $value =~ /^\d{1,3}(?:\.\d{1,3}){3}(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$/;
    return 1 if $value =~ /^[0-9A-Fa-f:]+(?:\/(?:[0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$/;
    debug_validation_failure('is_valid_ip_or_cidr', $value, 'does not match IPv4/IPv6 (with optional CIDR) pattern');
    return 0;
}

sub parse_web_filter_exception {
    my ($backup, $obj) = @_;
    my $data = $obj->{data};
    return [] if !defined $data;

    my @srcip;
    for my $network_ref (@{ensure_arrayref($data->{networks})}) {
        push @srcip, @{network_ref_to_cidr_list($backup, $network_ref)};
    }
    @srcip = grep { is_valid_ip_or_cidr($_) } @srcip;
    my %seen_srcip;
    @srcip = grep { !$seen_srcip{$_}++ } @srcip;

    my @domains;
    my $invalid_regex_count = 0;
    for my $value (@{ensure_arrayref($data->{domains})}) {
        my $normalized = normalize_webfilter_exception_regex($value);
        next if $normalized eq '';
        if (!is_valid_sfos_urlregex($normalized)) {
            $invalid_regex_count++;
            add_warning('http-exception', 'Dropped invalid URL regex after normalization for SFOS compatibility', {
                exception => $data->{name} // $obj->{ref},
                regex => $normalized,
            });
            next;
        }
        push @domains, $normalized;
    }
    if (!@domains && $invalid_regex_count > 0) {
        @domains = ('.*');
        add_warning('http-exception', 'All URL regex values became invalid after normalization; replaced with .* fallback', {
            exception => $data->{name} // $obj->{ref},
        });
    }
    my %seen_domains;
    @domains = grep { !$seen_domains{$_}++ } @domains;

    my @categories = @{names_for_refs($backup, $data->{sp_categories}, sub { resolve_url_category_name($_[0]) })};
    my @portable_categories = grep { $_ eq 'ALLWebTraffic' } @categories;
    if (@categories && !@portable_categories) {
        add_warning('http-exception', 'Dropped non-portable web categories from web filter exception', {
            exception => $data->{name} // $obj->{ref},
        });
    }
    @categories = @portable_categories;

    my %skip = map { $_ => 1 } @{ensure_arrayref($data->{skiplist})};
    my @policy_skip_sources = grep { $skip{$_} } qw(url_filter content_removal extensions contenttype_blacklist user_auth);
    my @unsupported_skip_sources = grep { $skip{$_} } qw(cache log_access log_blocked check_max_download patience);
    if (@unsupported_skip_sources) {
        add_warning('http-exception', 'UTM web exception skip selections include checks with no direct SFOS exception toggle; leaving them unmapped', {
            exception => $data->{name} // $obj->{ref},
            unmapped_checks => join(',', @unsupported_skip_sources),
        });
    }

    my $httpsdecrypt = $skip{ssl_scanning} ? 'on' : 'off';
    my $certvalidation = ($skip{certcheck} || $skip{certdate}) ? 'on' : 'off';
    my $virusscan = $skip{av} ? 'on' : 'off';
    my $zeroday = $skip{sandbox} ? 'on' : 'off';
    my $policycheck = @policy_skip_sources ? 'on' : 'off';
    if ($httpsdecrypt eq 'off' && $certvalidation eq 'off' && $virusscan eq 'off' && $zeroday eq 'off' && $policycheck eq 'off') {
        $policycheck = 'on';
        add_warning('http-exception', 'No SFOS-mappable web exception checks were selected from UTM skiplist; forcing PolicyCheck=on for SFOS validator compatibility', {
            exception => $data->{name} // $obj->{ref},
        });
    }

    if (!@srcip && !@domains && !@categories) {
        @domains = ('.*');
    }

    increment_stat('http.webfilter_exception');
    return {
        enabled => 1,
        name => escape_trunc($data->{name} // $obj->{ref}),
        description => escape_html($data->{comment} // ''),
        status => bool_to_on_off($data->{status}),
        httpsdecrypt => $httpsdecrypt,
        certvalidation => $certvalidation,
        virusscan => $virusscan,
        zeroday => $zeroday,
        policycheck => $policycheck,
        enable_srcip => (@srcip ? 'yes' : 'no'),
        enable_dstip => 'no',
        enable_urlregex => (@domains ? 'yes' : 'no'),
        enable_webcat => (@categories ? 'yes' : 'no'),
        srcip => [ map { { value => $_ } } @srcip ],
        dstip => [],
        urlregex => [ map { { value => $_ } } @domains ],
        webcat => [ map { { value => $_ } } @categories ],
    };
}

sub parse_backup {
    my ($backup, $requested_template) = @_;
    # if $requested_template is defined, we will only generate entities for it
    # otherwise, generate everything

    my %entities = ();
    my %extra = ();
    my %data_from_handlers = ();

    if (!defined $requested_template || $requested_template eq 'FirewallRule.tmpl') {
        my $geoip_firewall_rules = parse_geoip_firewall_rules($backup);
        if (ref($geoip_firewall_rules) eq 'ARRAY' && @$geoip_firewall_rules) {
            push @{ $entities{'FirewallRule.tmpl'} }, @{ make_entities('FirewallRule.tmpl', $geoip_firewall_rules) };
        }
    }

    for my $name (sort keys %{ $backup->{objects} // {} }) {
        my $obj = $backup->{objects}{$name};
        my $key = $obj->{class} . '/' . $obj->{type};
        next if $key eq 'packetfilter/packetfilter';
        my $template_name = $CLASS_TYPE_TO_TEMPLATE{$key};

        if (defined $CLASS_TYPE_HANDLERS{$key}) {
            my $handler = $CLASS_TYPE_HANDLERS{$key};
            push @{$data_from_handlers{$key}}, $handler->($backup, $obj);
        }

        if ($template_name) {
            next if defined $requested_template and $template_name ne $requested_template;
            my $handler = $TEMPLATE_METADATA{$template_name}->{handler};
            my ($template_data, $extra_data) = $handler->($backup, $obj);
            if ($template_name eq 'Host.tmpl' && $template_data) {
                $template_data = enrich_host_template_data($template_data, $obj);
            }
            if ($template_data) {
                push @{ $entities{$template_name} }, @{ make_entities $template_name, $template_data };
            }
            if ($extra_data) {
                my $index = scalar(@{ $entities{$template_name} // [] }) - 1;
                $index = 0 if $index < 0;
                while (my ($filename, $content) = each %$extra_data) {
                    $extra{$template_name}->{"$index/$filename"} = $content;
                }
            }
        }
    }

    # Handling the firewall rules separately to maintain their order
    my @rules = @{ensure_arrayref($backup->{main}->{packetfilter}->{rules})};
    for my $i (0 .. $#rules){
        my $obj = $backup->{objects}->{$rules[$i]};
        next if !$obj;
        my $key = $obj->{class} . '/' . $obj->{type};
        my $template_name = $CLASS_TYPE_TO_TEMPLATE{$key};

        if ($template_name) {
            next if defined $requested_template and $template_name ne $requested_template;
            my $handler = $TEMPLATE_METADATA{$template_name}->{handler};
            my ($template_data, $extra_data) = $handler->($backup, $obj);
            if ($template_name eq 'Host.tmpl' && $template_data) {
                $template_data = enrich_host_template_data($template_data, $obj);
            }
            if ($template_data) {
                push @{ $entities{$template_name} }, @{ make_entities $template_name, $template_data };
            }
        }
    }

    # create entities for templates that are not built from confd objects
    my @rest = grep {
        not exists $TEMPLATE_METADATA{$_}->{class_types}
        or scalar @{ $TEMPLATE_METADATA{$_}->{class_types} } == 0
    } keys %TEMPLATE_METADATA;

    if ($requested_template) {
        @rest = grep { $_ eq $requested_template } @rest;
    }

    for my $template_name (@rest) {
        my $metadata = $TEMPLATE_METADATA{$template_name};
        my ($template_data, $extra_data);
        if (defined $metadata->{handler}) {
            ($template_data, $extra_data) = $metadata->{handler}->($backup);
        }
        push @{ $entities{$template_name} }, @{ make_entities $template_name, $template_data };
        if ($extra_data) {
            my $index = scalar(@{ $entities{$template_name} // [] }) - 1;
            $index = 0 if $index < 0;
            while (my ($filename, $content) = each %$extra_data) {
                $extra{$template_name}->{"$index/$filename"} = $content;
            }
        }
    }

    while (my ($template_name, $metadata) = each %POST_HANDLERS) {
        # TODO DRY - same logic as for processing backup objects
        next if defined $requested_template and $template_name ne $requested_template;
        my @params = map { $data_from_handlers{$_} // [] } @{ $metadata->{class_types} };
        my ($template_data, $extra_data) = $metadata->{handler}->(@params);
        push @{ $entities{$template_name} }, @{ make_entities $template_name, $template_data };
        if ($extra_data) {
            my $index = scalar(@{ $entities{$template_name} // [] }) - 1;
            $index = 0 if $index < 0;
            while (my ($filename, $content) = each %$extra_data) {
                $extra{$template_name}->{"$index/$filename"} = $content;
            }
        }
    };

    return \%entities, \%extra;
}

sub summary {
    my ($entities, $extra_data) = @_;

    for my $k (sort keys %$entities) {
        my $count_entities = scalar @{ $entities->{$k} };
        my $count_extra_data = 0;
         if (defined $extra_data->{$k}) {
            $count_extra_data = scalar keys %{ $extra_data->{$k} };
        }
        my $summary = "summary for $k: $count_entities entities";
        $summary .= ", $count_extra_data extra" if $count_extra_data > 0;
        say STDERR $summary;
    }
    say STDERR "warnings collected: " . scalar(@{ $MIGRATION_REPORT{warnings} });
    return;
}

sub enforce_contract_guardrails {
    my ($entities) = @_;
    my @update_only_templates = (
        'ATP.tmpl',
        'Time.tmpl',
        'DoSSettings.tmpl',
        'PIMDynamicRouting.tmpl',
    );
    for my $template (@update_only_templates) {
        my $count = scalar @{ $entities->{$template} // [] };
        if ($count > 1) {
            add_warning('sfos-contract', "Template $template is update-only and should emit at most one entity", {
                template => $template,
                count => $count,
            });
        }
    }

    for my $entity (@{ $entities->{'FirewallRule.tmpl'} // [] }) {
        if ($entity =~ m|<HTTPBasedPolicy>|) {
            add_warning('sfos-contract', 'Forward firewall rule template emitted HTTPBasedPolicy unexpectedly');
        }
    }
}

sub get_xml_from_entities {
    my ($entities) = @_;
    my $xml =
        join "\n",
        map { join "\n", @{ $entities->{$_} } }
        grep { @{ $entities->{$_} } }
        grep { exists $entities->{$_} }
        @ORDER;
    return $xml;
}

sub make_export_tar {
    my ($entities, $extra_data) = @_;
    my $tar = Archive::Tar->new;
    my $xml = encode("utf-8", get_xml_from_entities ($entities));
    $tar->add_data('Entities.xml', $xml);

    for my $template (keys %$extra_data) {
        my $metadata = $TEMPLATE_METADATA{$template};
        my $path = $metadata->{extra_data_path};

        while (my ($filename, $content) = each %{ $extra_data->{$template} } ) {
            $tar->add_data($path . $filename, $content);
        }
    }
    return $tar;
}

sub parse_command_line_args {
    my $backup_path;
    my $template_name;
    my $output_file = 'Export.tar';
    my %opt;
    my @raw_argv = @ARGV;
    my $debug_level = parse_debug_level_from_argv(\@raw_argv);

    getopts('Flhdi:o:p:D:s:N:R:I:', \%opt);
    usage() if $opt{h};
    usage() if (defined $opt{i} && ($opt{i} eq '' || ! -f $opt{i}));
    usage() if (defined $opt{o} && $opt{o} eq '');
    usage() if (defined $opt{p} && $opt{p} eq '');
    usage() if (defined $opt{D} && $opt{D} eq '');
    usage() if (defined $opt{s} && $opt{s} eq '');
    usage() if (defined $opt{N} && $opt{N} !~ /^(safe|compat)$/);
    $template_name = $opt{s} if (defined $opt{s});
    $output_file = $opt{o} if (defined $opt{o});
    $DEFAULT_INTERFACE_NAME = $opt{p} if (defined $opt{p});
    $DEFAULT_DHCP_INTERFACE_NAME = $opt{D} if (defined $opt{D});
    $backup_path = $opt{i} if (defined $opt{i});
    $DEBUG = $debug_level if $debug_level > 0;
    $DEBUG = 1 if $opt{d} && $DEBUG < 1;
    $LOG_FIREWALL = 1 if (defined $opt{l});
    $MIGRATE_FIREWALL_RULES = 0 if (defined $opt{F});
    $NAT_STRATEGY = $opt{N} if (defined $opt{N});

    $MIGRATION_REPORT_FILE = $opt{R} if (defined $opt{R});

    if (defined $opt{I}) {
        if ($opt{I} eq '') {
            usage();
        }
        $INTERFACE_ROUTE_NAME = $opt{I};
    }

    return ($template_name, $output_file, $backup_path);
}

sub main {
    my ($template_name, $output_file, $backup_path) = parse_command_line_args();
    if (not $backup_path) {
        # Generate current snapshot
        my $snapshot_name = `$CONFD snapshot_create`;
        $snapshot_name =~ s/\s+$//;
        $backup_path = "$SNAPSHOT_DIR$snapshot_name";
    }

    say STDERR "Using confd snapshot $backup_path";
    my $backup = read_backup $backup_path;
    say STDERR 'confd objects in backup: ', scalar keys %{ $backup->{objects} } if $DEBUG;

    say STDERR "will only output template $template_name" if $template_name;
    my ($entities, $extra_data) = parse_backup $backup, $template_name;
    enforce_contract_guardrails($entities);
    summary($entities, $extra_data);

    if (defined $template_name) {
        # Dry run / testing single template output. Print to STDOUT
        binmode STDOUT, ':encoding(utf8)';
        local $|=1;
        for my $entity (@{ $entities->{$template_name} }) {
            say $entity;

        }
    } else {
        # Full run. Print to $output_file
        say STDERR "Exporting objects from $backup_path to $output_file";
        my $tar = make_export_tar $entities, $extra_data;
        $tar->write($output_file);
        my $report_file = $MIGRATION_REPORT_FILE || ($output_file . '.report.json');
        if (open my $report_fh, '>', $report_file) {
            print {$report_fh} build_migration_report_json();
            close $report_fh;
            say STDERR "Migration report written to $report_file";
        } else {
            warn "Could not write migration report to $report_file: $!";
        }
        say STDERR "Export complete";
    }
    return;
}

__PACKAGE__->main(@ARGV) unless caller();
