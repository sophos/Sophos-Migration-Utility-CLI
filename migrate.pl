#!/usr/bin/perl
#Copyright Sophos Ltd 2023
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

our $VERSION = '0.4';
# Sophos Migration Utility - CLI
# Compatible with UTM 9.7xx to SFOS 19.5.1
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
# 3. DNS Groups -> IPLists is disabled - See DNSGrouptoIPLIST in sub parse_hosts() to re-enable
# 4. Gateway hosts -> Gateways only supports IPv4 (SFOS restriction)

# 5. SFOS validates the VPN connections more strictly than UTM.  Because of this, some configurations that are valid in UTM will be silently rejected by SFOS.
# It is not feasible to reimplement all the SFOS validation rules, so this tool will only detect a limited number of issues that may cause problems, as mentioned below.  Please be advised there may be more situations that will cause SFOS to reject the settings.
#     - Pre-shared key length must be at least 5 characters
#     - VPN connections must have well defined networks - can't use "Any" as network definitions

# 6. This version will import the local ID (usually a hostname) from UTM into SFOS.
# 7. Users and groups are not imported.  For VPN definitions, they have to be added manually.
#
## Supported exports
#   - Web Filter Action Allow and Block lists -> URL Groups
#   - Website tags -> URL Groups
#   - TCP, UDP, and TCP/UDP Services -> TCPorUDP Services
#   - ICMP Services -> ICMP Services
#   - ICMPv6 Services -> ICMPv6 Services
#   - IP Services -> IP Services
#   - Host Definitions -> FQDN Hosts, IP Hosts IPs (IPv4 and IPv6), and MACs
#   - Network Definitions -> IP Host Networks (IPv4 and IPv6)
#   - IP Ranges -> IP Host Ranges (IPv4 and IPv6)
#   - DNS Group hostname -> FQDNHost
#   - Gateway Hosts -> Gateways (IPv4)
#    - VPN Settings - site-to-site
#    - VPN Settings - SSL VPN remote access
#
## Unsupported exports to be considered
#   - VPN Settings - remote access
#   - Routes
#   - VLANs
#   - Firewall rules

my $DEBUG = 0;
my $CONFD = "/usr/local/bin/confd-client.plx";
my $SNAPSHOT_DIR = "/var/confd/var/storage/snapshots/";
my $HTML_TEMPLATE_DIR = './tmpl/';
my $DEFAULT_INTERFACE_NAME = 'Port1';

use lib '.';
use Protocols qw/$IP_PROTOS $ICMP4 $ICMP6/;

our %TEMPLATE_METADATA = (
    'Header.tmpl' => { },
    'Footer.tmpl' => { },
    'GatewayHost.tmpl' => { handler => \&parse_one_gatewayhost, class_types => ['itfparams/primary', 'route/policy'] },
    'Host.tmpl' => { handler => \&parse_one_host, class_types => ['network/dns_host', 'network/host', 'network/network', 'network/interface_network', 'network/range', 'network/dns_group'] },
    'URLGroup.tmpl' => { handler => \&parse_one_url_group, class_types => ['http/cff_action'] },
    'Services.tmpl' => { handler => \&parse_one_service, class_types => ['service/tcp', 'service/udp', 'service/tcpudp', 'service/icmp', 'service/icmpv6', 'service/ip'] },
    # this is used for both s2s and remote access!
    'SSLTunnelAccessSettings.tmpl' => { handler => \&parse_ssl_tunnel_access_settings, class_types => [] },
    'Certificate.tmpl' => { handler => \&parse_one_certificate, class_types => ['ca/host_key_cert'], extra_data_path => 'Files/CertificateFile/0/' },
    'VPNProfile.tmpl' => { handler => \&parse_one_ipsec_vpn_profile, class_types => ['ipsec/policy'] },
    'VPNIPSecConnection.tmpl' => { handler => \&parse_one_ipsec_vpn_connection, class_types => ['ipsec_connection/site_to_site'] },
    'SiteToSiteServer.tmpl' => { handler => \&parse_one_ssl_vpn_server, class_types => ['ssl_vpn/server_connection'] },
    'SiteToSiteClient.tmpl' => { handler => \&parse_one_ssl_vpn_client, class_types => ['ssl_vpn/client_connection'], extra_data_path => 'Files/ServerConfigurationFile/0/' },
    'PPTPConfiguration.tmpl' => { handler => \&parse_remote_access_pptp_configuration },
    'SSLVPNPolicy.tmpl' => { handler => \&parse_remote_access_ssl_vpn, class_types => [ 'ssl_vpn/remote_access_profile' ] },
);

our %CLASS_TYPE_TO_TEMPLATE;
while (my ($template_name, $data) = each %TEMPLATE_METADATA) {
    my $class_type_list = $data->{class_types};
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
    'GatewayHost.tmpl',
    'Services.tmpl',
    'URLGroup.tmpl',
    'Certificate.tmpl',
    'VPNProfile.tmpl',
    'VPNIPSecConnection.tmpl',
    'SSLTunnelAccessSettings.tmpl',
    'SiteToSiteServer.tmpl',
    'SiteToSiteClient.tmpl',
    'PPTPConfiguration.tmpl',
    'SSLVPNPolicy.tmpl',
    'SophosConnection.tmpl',
    'Footer.tmpl',
);

# helper functions

sub usage {
    say STDERR "Sophos Migration Utility CLI for UTM to SFOS - Version $VERSION";
    say STDERR "USAGE: $0 [-i path/to/snapshot] [-o path/to/Export.tar] [-d]";
    say STDERR "\t-i\t- Path to a specific UTM snapshot to be exported.\n\t\t  Usually located in /var/confd/var/storage/snapshots/";
    say STDERR "\t\t  If -i is not specified, a snapshot of the current UTM configuration will be created and used.";
    say STDERR "\t-o\t- Optional export path for the SFOS compatible TAR file.\n\t\t  Default: ./Export.tar";
    say STDERR "\t-d\t- Optional flag to enable debug output\n\t\t  Default: off";
    say STDERR "\t-s\t- Optional path to only export a single template type. For development purposes only.";
    say STDERR "\t-p\t- Optional SFOS interface name.\n\t\t  Default: $DEFAULT_INTERFACE_NAME";
    say STDERR "\t-h\t- Display this help / usage message.";
    say STDERR "Important: This tool is meant to be run on Sophos UTM / ASG systems. Usage on other systems may require you to";
    say STDERR "convert the snapshot file (see util/convert_snapshot.pl), and will require the -i option.";
    exit;
}

sub read_backup {
    my ($fn) = @_;
    -f $fn or die $!;
    return retrieve $fn;
}

sub cidr_to_netmask {
    my ($cidr) = @_;
    return join '.', unpack 'C4', pack 'N', (2**$cidr-1) << (32 - $cidr);
}

sub get_ref {
    my ($backup, $ref_name) = @_;
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
    $s = escape_html($s);
    $s = trunc($s,$len);
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
    my ($network_obj) = @_;
    my $host = @{ parse_one_host (undef, $network_obj) }[0];
    return { name => $host->{name} };
}

sub split_array {
    # destructive
    my ($n, $aref) = @_;
    my @ret;
    push @ret, [ splice @$aref, 0, $n ] while @$aref;
    return \@ret;
}

sub parse_one_host_from_dns_host {
    my ($backup, $obj) = @_;
    my @ret = ();
    push @ret, {
        fqdn => 1,
        name => escape_trunc("DNS Host: ".$obj->{data}->{name}),
        type => 'FQDN',
        address => $obj->{data}->{hostname}
    };

    if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && $obj->{data}->{address} ne "0.0.0.0") {
        #DNS Host is resolved, create an IP Host
        push @ret, {
            iphost => 1,
            name => escape_trunc("DNS Host IP: ".$obj->{data}->{name}),
            type => 'IP',
            family => 'IPv4',
            address => $obj->{data}->{address}
        };
    }

    if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && $obj->{data}->{address6} ne "::") {
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
    if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && $obj->{data}->{address} ne "0.0.0.0") {
        push @ret, {
            iphost => 1,
            name => escape_trunc("Host IP: ".$obj->{data}->{name}),
            type => 'IP',
            family => 'IPv4',
            address => $obj->{data}->{address}
        };
    }

    if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && $obj->{data}->{address6} ne "::") {
        push @ret, {
            iphost => 1,
            name => escape_trunc("Host IPv6: ".$obj->{data}->{name}),
            type => 'IP',
            family => 'IPv6',
            address => $obj->{data}->{address6}
        };
    }

    my @hostnames = @{ $obj->{data}->{hostnames} };
    my $i = 1;
    foreach my $hostname (@hostnames) {
        push @ret, {
            fqdn => 1,
            name => "IP Host DNS: " . escape_trunc($obj->{data}->{name}, 40) . " $i",
            type => 'FQDN',
            address => $hostname
        };
        $i++;
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
            subnet => cidr_to_netmask($obj->{data}->{netmask})
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

sub parse_one_host_from_dns_group {
    my ($backup, $obj) = @_;
    my @ret = ();
    push @ret, {
        fqdn => 1,
        name => escape_trunc("DNS Group FQDN: ".$obj->{data}->{name}),
        type => 'FQDN',
        address => $obj->{data}->{hostname}
    };
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
        if ($_ eq 'dns_host') {
            return parse_one_host_from_dns_host $backup, $obj;
        } elsif ($_ eq 'host') {
            return parse_one_host_from_host $backup, $obj;
        } elsif ($_ eq 'network' or $_ eq 'interface_network') {
            return parse_one_host_from_network $backup, $obj;
        } elsif ($_ eq 'range') {
            return parse_one_host_from_range $backup, $obj;
        } elsif ($_ eq 'dns_group') {
            return parse_one_host_from_dns_group $backup, $obj;
        }
    }
    return \@ret;
}

sub parse_one_gatewayhost {
    my ($backup, $obj) = @_;
    my $class_type = $obj->{class} . '/' . $obj->{type};

    if ($class_type eq 'itfparams/primary') {
        # interface
        return {
            name => $obj->{data}->{name},
            gateway_ip => $obj->{data}->{default_gateway_address},
        };
    } elsif ($class_type eq 'route/policy') {
        # route
        return {
            name => $obj->{data}->{name},
            gateway_ip => get_ref($backup, $obj->{data}->{target})->{address},
        };
    }
}

sub parse_one_service {
    my ($backup, $obj) = @_;
    my $data = $obj->{data};
    my $type = $obj->{type};

    my %SERVICE_TYPE_MAP = ( tcp => 'TCPorUDP', udp => 'TCPorUDP', tcpudp => 'TCPorUDP', ip => 'IP', icmp => 'ICMP', icmpv6 => 'ICMPv6' );

    # SFOS only supports service types TCP, UDP, IP, ICMP, and ICMPv6, so don't bother processing the rest. TCPUDP will be split into two separate services

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
    # SFOS doesn't support regex URL Groups, so we can't import it
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
        warn "IPSec VPN connection $data->{name} can't use Any networks - found: @any_networks";
        return;
    }

    my $local_subnets = [
        map { network_name get_ref($backup, $_) } @{$obj->{data}->{networks}}
    ];

    my $remote_networks = [
        map { network_name get_ref($backup, $_) } @{$remote_gateway->{data}->{networks}}
    ];

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
        remote_id => $remote_auth->{data}->{vpn_id},
        # These should contain the local interface name, but interface names are different between UTM and SFOS!
        # We will use a global default here.
        # For the future, the way to get the UTM interface is: `get_ref($backup, $data->{interface})->{data}->{name}`
        local_address => $DEFAULT_INTERFACE_NAME,
        local_gateway => $DEFAULT_INTERFACE_NAME,
    };

    my $confd_ipsec = $backup->{main}->{ipsec};
    my $local_rsa = get_ref($backup, $confd_ipsec->{local_rsa});
    $vpn->{local_id_type} = $vpn_id_types{$local_rsa->{data}->{vpn_id_type}};
    $vpn->{local_id} = $local_rsa->{data}->{vpn_id};

    return $vpn;
}

sub parse_ssl_tunnel_access_settings {
    my ($backup) = @_;

    my $s = $backup->{main}->{ssl_vpn};
    my $ip_assignment_pool = get_ref($backup, $s->{ip_assignment_pool});
    if ($ip_assignment_pool->{class} ne 'network' or $ip_assignment_pool->{type} ne 'network') {
        die 'auth object is of wrong type';
    };

    my $fn = sanitize_name(get_ref($backup, $s->{certificate})->{data}->{name});

    my %ret = (
        protocol => uc($s->{protocol}), # TODO map?
        certificate => $fn,
        hostname => undef, # FIXME OverrideHostname or HostorDNSName?
        port => $s->{port},
        start_ip => $ip_assignment_pool->{data}->{address},
        subnet_mask => cidr_to_netmask($ip_assignment_pool->{data}->{netmask}),
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

sub parse_one_ssl_vpn_server {
    my ($backup, $obj) = @_;

    my @any_networks = grep {
        is_any_network get_ref($backup, $_)
    } @{$obj->{data}->{local_networks}}, @{$obj->{data}->{remote_networks}};

    if (@any_networks) {
        warn "SSL VPN connection $obj->{data}->{name} can't use Any networks - found: @any_networks";
        return;
    }

    my @local_networks = map { network_name get_ref($backup, $_) } @{$obj->{data}->{local_networks}};
    my @remote_networks = map { network_name get_ref($backup, $_) } @{$obj->{data}->{remote_networks}};

    return {
        name => $obj->{data}->{name},
        static_ip => ($obj->{data}->{static_ip_status} ? 'Disable' : 'Enable'),
        local_networks => \@local_networks,
        remote_networks => \@remote_networks,
        status => ($obj->{data}->{status} ? 'On' : 'Off'),
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

    my $filename = $HTML_TEMPLATE_DIR . $template_name;
    my $template = HTML::Template->new(filename => $filename, utf8 => 1, debug => $DEBUG, die_on_bad_params => 0)
        or die "Template creation failed";
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
        primary_dns => $advanced->{msdns1},
        secondary_dns => $advanced->{msdns2},
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
            map { network_name get_ref($backup, $_) } @{$obj->{data}->{networks}}
        ],
        disconnect_idle_clients => 'On',
        override_global_timeout_minutes => 15
    };
}

sub calculate_ip_range {
    my ($ip, $netmask) = @_;
    use Socket qw/inet_aton inet_ntoa/;  # TODO move to top?
    my $nip = inet_aton $ip;
    my $nmask = inet_aton $netmask;
    my $first = inet_ntoa ($nip & $nmask);
    my $last = inet_ntoa ($nip | ~$nmask);

    return ($first, $last);
}

sub parse_backup {
    my ($backup, $requested_template) = @_;
    # if $requested_template is defined, we will only generate entities for it
    # otherwise, generate everything

    my %entities = ();
    my %extra = ();
    my %data_from_handlers = ();

    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        my $key = $obj->{class} . '/' . $obj->{type};
        my $template_name = $CLASS_TYPE_TO_TEMPLATE{$key};

        if ($template_name) {
            next if defined $requested_template and $template_name ne $requested_template;
            my $handler = $TEMPLATE_METADATA{$template_name}->{handler};
            my ($template_data, $extra_data) = $handler->($backup, $obj);
            push @{ $entities{$template_name} }, @{ make_entities $template_name, $template_data };
            if ($extra_data) {
                while (my ($filename, $content) = each %$extra_data) {
                    $extra{$template_name}->{$filename} = $content;
                }
            }

        } elsif (defined $CLASS_TYPE_HANDLERS{$key}) {
            my $handler = $CLASS_TYPE_HANDLERS{$key};
            push @{$data_from_handlers{$key}}, $handler->($backup, $obj);

        } else {
            # class/type not handled
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
            while (my ($filename, $content) = each %$extra_data) {
                $extra{$template_name}->{$filename} = $content;
            }
        }
    }

    while (my ($template_name, $metadata) = each %POST_HANDLERS) {
        # TODO DRY - same logic as for processing backup objects
        next if defined $requested_template and $template_name ne $requested_template;
        my @params = map { $data_from_handlers{$_} } @{ $metadata->{class_types} };
        my ($template_data, $extra_data) = $metadata->{handler}->(@params);
        push @{ $entities{$template_name} }, @{ make_entities $template_name, $template_data };
        if ($extra_data) {
            while (my ($filename, $content) = each %$extra_data) {
                $extra{$template_name}->{$filename} = $content;
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
    return;
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
    my $xml = get_xml_from_entities $entities;
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

    getopts('hdi:o:s:', \%opt);
    usage() if $opt{h};
    usage() if (defined $opt{i} && ($opt{i} eq '' || ! -f $opt{i}));
    usage() if (defined $opt{o} && $opt{o} eq '');
    usage() if (defined $opt{s} && $opt{s} eq '');
    $template_name = $opt{s} if (defined $opt{s});
    $output_file = $opt{o} if (defined $opt{o});
    $backup_path = $opt{i} if (defined $opt{i});
    $DEBUG = 1 if $opt{d};

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
        my $tar = make_export_tar $entities, $extra_data, $output_file;
        $tar->write($output_file);
        say STDERR "Export complete";
    }
    return;
}

__PACKAGE__->main(@ARGV) unless caller();