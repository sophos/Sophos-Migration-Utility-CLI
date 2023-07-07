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

our $VERSION = '0.3';
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
#   - VPN Settings - site-to-site only
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

my %SERVICE_TYPE_MAP = ( tcp => 'TCPorUDP', udp => 'TCPorUDP', tcpudp => 'TCPorUDP', ip => 'IP', icmp => 'ICMP', icmpv6 => 'ICMPv6' );

# order matters
our @TEMPLATE = (
    [ 'Host.tmpl', \&prepare_hosts ],
    [ 'GatewayHost.tmpl', \&prepare_gatewayhost ],
    [ 'Services.tmpl', \&prepare_services ],
    [ 'URLGroup.tmpl', \&prepare_urlgroup ],
    [ 'Certificate.tmpl', \&prepare_certificates ],
    [ 'VPNProfile.tmpl', \&prepare_ipsec_vpn_profile ],
    [ 'VPNIPSecConnection.tmpl', \&prepare_ipsec_vpn_connections ],
    [ 'SSLTunnelAccessSettings.tmpl', \&prepare_ssl_tunnel_access_settings ],
    [ 'SiteToSiteServer.tmpl', \&prepare_ssl_vpn_servers ],
    [ 'SiteToSiteClient.tmpl', \&prepare_ssl_vpn_clients ],
);

my %TEMPLATE = map { $_->[0] => $_->[1] } @TEMPLATE;

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
    retrieve $fn
}

sub cidr_to_netmask {
    my ($cidr) = @_;
    join '.', unpack 'C4', pack 'N', (2**$cidr-1) << (32 - $cidr)
}

sub parse_one_host {
    my ($obj) = @_;
    my @ret = ();

    for ($obj->{type}) {
        if ($_ eq 'dns_host') {
            push @ret, {
                name => escape_trunc("DNS Host: ".$obj->{data}->{name}),
                type => 'FQDN',
                address => $obj->{data}->{hostname}
            };

            if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && $obj->{data}->{address} ne "0.0.0.0") {
                #DNS Host is resolved, create an IP Host
                push @ret, {
                    name => escape_trunc("DNS Host IP: ".$obj->{data}->{name}),
                    type => 'IP',
                    family => 'IPv4',
                    address => $obj->{data}->{address}
                };
            }

            if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && $obj->{data}->{address6} ne "::") {
                push @ret, {
                    name => escape_trunc("DNS Host IPv6: ".$obj->{data}->{name}),
                    type => 'IP',
                    family => 'IPv6',
                    address => $obj->{data}->{address6}
                };
            }
        } elsif ($_ eq 'host') {
            if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && $obj->{data}->{address} ne "0.0.0.0") {
                push @ret, {
                    name => escape_trunc("Host IP: ".$obj->{data}->{name}),
                    type => 'IP',
                    family => 'IPv4',
                    address => $obj->{data}->{address}
                };
            }

            if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && $obj->{data}->{address6} ne "::") {
                push @ret, {
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
                    name => escape_trunc("IP Host MACs: ".$obj->{data}->{name}),
                    type => 'MACList',
                    macs => \@macs
                };
            }
        } elsif ($_ eq 'network' or $_ eq 'interface_network') {
            if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && $obj->{data}->{address} ne "0.0.0.0") {
                push @ret, {
                    name => escape_trunc("Network: ".$obj->{data}->{name}),
                    type => 'Network',
                    family => 'IPv4',
                    address => $obj->{data}->{address},
                    subnet => cidr_to_netmask($obj->{data}->{netmask})
                };
            }
            if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && $obj->{data}->{address6} ne "::") {
                push @ret, {
                    name => escape_trunc("Network IPv6: ".$obj->{data}->{name}),
                    type => 'Network',
                    family => 'IPv6',
                    address => $obj->{data}->{address6},
                    subnet => $obj->{data}->{netmask6}
                };
            }
        } elsif ($_ eq 'range') {
            if ($obj->{data}->{from} && $obj->{data}->{from} ne "") {
                push @ret, {
                    name => escape_trunc("Range: ".$obj->{data}->{name}),
                    type => 'Range',
                    family => 'IPv4',
                    start_address => $obj->{data}->{from},
                    end_address => $obj->{data}->{to}
                };
            }
            if ($obj->{data}->{from6} && $obj->{data}->{from6} ne "") {
                push @ret, {
                    name => escape_trunc("Range IPv6: ".$obj->{data}->{name}),
                    type => 'Range',
                    family => 'IPv6',
                    start_address => $obj->{data}->{from6},
                    end_address => $obj->{data}->{to6}
                };
            }
        } elsif ($_ eq 'dns_group') {

            push @ret, {
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
        }
    }
    \@ret
}

sub parse_hosts {
    my ($backup) = @_;
    my @ret = ();
    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        next unless $obj->{class} eq 'network';
        next if ($obj->{type} eq 'group' ||
                 $obj->{type} eq 'multicast' ||
                 $obj->{type} eq 'availability_group');

        my $results = parse_one_host $obj;
        push @ret, @$results;

    }
    \@ret
}

sub parse_interfaces {
    my ($backup) = @_;
    my @ret = ();
    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        next unless $obj->{class} eq 'itfparams';
        if ($obj->{type} eq 'primary') {
            # TODO deal with vlans
        }
        next unless $obj->{data}->{address};
        (my $name = $obj->{data}->{name}) =~ tr/./_/;
        push @ret, {
            ipaddr => $obj->{data}->{address},
            name => $name,
            model => $name,
            netmask => cidr_to_netmask($obj->{data}->{netmask} // 24),
            default_gw => $obj->{data}->{default_gateway_address},
            primary => $obj->{data}->{dns_server_1},
            secondary => $obj->{data}->{dns_server_2},
            tertiary => $obj->{data}->{dns_server_3}
        };
        # if ($obj->{data}->{ipaddr} && $obj->{data}->{netmask}) { ... }

    }

    # TODO handle vlans here
    \@ret
}

sub get_ref {
    my ($backup, $ref_name) = @_;
    $backup->{objects}{$ref_name}
}

sub parse_routes {
    my ($backup) = @_;
    my @ret;
    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        next unless $obj->{class} eq 'route' and $obj->{type} eq 'policy';
        push @ret, {
            name => $obj->{data}->{name},
            comment => escape_html($obj->{data}->{comment}),
            src => get_ref($backup, $obj->{data}->{source})->{address},
            # src_display =>
            dest => get_ref($backup, $obj->{data}->{destination})->{name}, # TODO why not address?
            # dst_display =>
            service => get_ref($backup, $obj->{data}->{service})->{name},
            # svc_display =>
            interface => $obj->{data}->{interface},
            gateway => get_ref($backup, $obj->{data}->{target})->{name},
            gateway_ip => get_ref($backup, $obj->{data}->{target})->{address},
        };
    }
    \@ret
}

sub port_range {
    my ($low, $high) = @_;
    $low eq $high ? $low : "$low:$high"
}

sub parse_one_service {
    # For services of type 'tcpudp' this sub can actually return two hashrefs,
    # one for tcp and one for udp.
    my ($obj) = @_;
    my $data = $obj->{data};
    my $type = $obj->{type};

    my @ret;

    #SFOS only supports service types TCP, UDP, IP, ICMP, and ICMPv6, so don't bother processing the rest. TCPUDP will be split into two separate services
    return \@ret if (!$type || !($type eq 'tcp' || $type eq 'udp' || $type eq 'tcpudp' || $type eq 'icmp' || $type eq 'icmpv6' || $type eq 'ip'));

    my %service = (
        name => escape_trunc($data->{name}),
        type => $SERVICE_TYPE_MAP{$type},
    );

    for ($type) {
        if ($_ eq 'tcp') {
            $service{details}[0] = { port_src => port_range($data->{src_low}, $data->{src_high}),
                                    port_dst => port_range($data->{dst_low}, $data->{dst_high}),
                                    protocol => 'TCP' };
            push @ret, \%service;
        } elsif ($_ eq 'udp') {
            $service{details}[0] = { port_src => port_range($data->{src_low}, $data->{src_high}),
                                    port_dst => port_range($data->{dst_low}, $data->{dst_high}),
                                    protocol => 'UDP' };
            push @ret, \%service;
        } elsif ($_ eq 'tcpudp') {
            $service{details}[0] = { port_src => port_range($data->{src_low}, $data->{src_high}),
                                    port_dst => port_range($data->{dst_low}, $data->{dst_high}),
                                    protocol => 'TCP' };
            $service{details}[1] = { port_src => port_range($data->{src_low}, $data->{src_high}),
                                    port_dst => port_range($data->{dst_low}, $data->{dst_high}),
                                    protocol => 'UDP' };
            push @ret, \%service;
        } elsif ($_ eq 'ip') {
            $service{protocol_name} = $IP_PROTOS->{$data->{proto}};
            push @ret, \%service;
        } elsif ($_ eq 'icmp') {
            $service{icmp_type} = $ICMP4->{$data->{type}}->{name};
            $service{icmp_code} = $ICMP4->{$data->{type}}->{$data->{code}} || 'Any code';
            push @ret, \%service;
        } elsif ($_ eq 'icmpv6') {
            $service{icmp_type} = $ICMP6->{$data->{type}}->{name};
            $service{icmp_code} = $ICMP6->{$data->{type}}->{$data->{code}} || 'Any code';
            push @ret, \%service;
        }
    }

    \@ret
}

sub parse_services {
    my ($backup) = @_;
    my @ret;
    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        next unless $obj->{class} eq 'service' and $obj->{type} ne 'group';
        push @ret, @{ parse_one_service $obj };
    }
    \@ret
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

sub prepare_gatewayhost {
    my ($template, $backup) = @_;
    my @ret;

    my $interfaces = parse_interfaces $backup;
    my $routes = parse_routes $backup;

    for my $i (@$interfaces) {
        push @ret, {
            name => escape_trunc($i->{default_gw}), #TODO: Use generated name if empty
            gateway_ip => $i->{default_gw}
        }
    }

    for my $r (@$routes) {
        push @ret, {
            name => escape_trunc($r->{gateway}), #TODO: Use generated name if empty
            gateway_ip => $r->{gateway_ip}
        }
    }

    $template->param(objects => \@ret);
}

sub prepare_hosts {
    my ($template, $backup) = @_;
    my (@fqdns, @ips, @ranges, @networks, @iplists, @maclists);

    my $hosts_backup = parse_hosts $backup;
    for my $host (@$hosts_backup) {
        for ($host->{type}) {
            if ($_ eq 'IP') {
                push @ips, $host;
            } elsif ($_ eq 'Range') {
                push @ranges, $host;
            } elsif ($_ eq 'Network') {
                push @networks, $host;
            } elsif ($_ eq 'FQDN') {
                push @fqdns, $host;
            } elsif ($_ eq 'IPList') {
                push @iplists, $host;
            } elsif ($_ eq 'MACList') {
                push @maclists, $host;
            }
        }
    }

    $template->param(
        ips         => \@ips,
        ranges      => \@ranges,
        networks    => \@networks,
        fqdns       => \@fqdns,
        iplists     => \@iplists,
        maclists    => \@maclists);
}

sub prepare_services {
    my ($template, $backup) = @_;
    my $services = parse_services $backup;
    say STDERR 'services count: ', scalar @$services if $DEBUG;
    my (@tcpudp, @ip, @icmp, @icmpv6);

    for my $s (@$services) {
        for ($s->{type}) {
            if ($_ eq 'TCPorUDP') {
                push @tcpudp, $s;
            } elsif ($_ eq 'IP') {
                push @ip, $s;
            } elsif ($_ eq 'ICMP') {
                push @icmp, $s;
            } elsif ($_ eq 'ICMPv6') {
                push @icmpv6, $s;
            }
        }
    }

    say STDERR "services stats: ",
        join(' ',
            "tcpudp", scalar @tcpudp,
            "ip", scalar @ip,
            "icmp", scalar @icmp,
            "icmpv6", scalar @icmpv6) if $DEBUG;

    $template->param(
        tcpudp => \@tcpudp,
        ip => \@ip,
        icmp => \@icmp,
        icmpv6 => \@icmpv6,
    )
}

sub prepare_urlgroup {
    my ($template, $backup) = @_;
    my @ret = ();

    #Parse Filter Action white/blacklists and convert them to URL Groups
    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        next if ! ( $obj->{type} eq 'cff_action' && $obj->{class} eq 'http' );

        my $full_name = escape_html($obj->{data}->{name});
        my $trunc_name = trunc($full_name, 30);
        my @whitelist;
        my @blacklist;

        foreach my $domain_ref (@{ $obj->{data}->{url_whitelist} }) {
            foreach my $domain (@{ $backup->{objects}->{$domain_ref}->{data}->{domain} }) {
                next if ($domain =~ /[^a-zA-Z0-9.-]/); #SFOS doesn't support regex URL Groups, so we can't import it
                push @whitelist, {url => $domain};
            }
        }
        foreach my $domain_ref (@{ $obj->{data}->{url_blacklist} }) {
            foreach my $domain (@{ $backup->{objects}->{$domain_ref}->{data}->{domain} }) {
                next if ($domain =~ /[^a-zA-Z0-9.-]/); #SFOS doesn't support regex URL Groups, so we can't import it
                push @blacklist, {url => $domain};
            }
        }
        if (@whitelist) {
            if (@whitelist > 128) { #URL Group is too big, need to split
                my $loop = 1;
                while (my @list = splice(@whitelist, 0, 128)) {
                    push @ret, {
                        name => $full_name,
                        trunc_name => $trunc_name." $loop",
                        type => "allow",
                        urls => \@list
                    };
                    $loop++;
                }
            } else {
                push @ret, {
                    name => $full_name,
                    trunc_name => $trunc_name,
                    type => "allow",
                    urls => \@whitelist
                };
            }
        }
        if (@blacklist) {
            if (@blacklist > 128) { #URL Group is too big, need to split
                my $loop = 1;
                while (my @list = splice(@blacklist, 0, 128)) {
                    push @ret, {
                        name => $full_name,
                        trunc_name => $trunc_name." $loop",
                        type => "block",
                        urls => \@list
                    };
                    $loop++;
                }
            } else {
                push @ret, {
                    name => $full_name,
                    trunc_name => $trunc_name,
                    type => "block",
                    urls => \@blacklist
                };
            }
        }
    }

    #Parse tagged websites and convert them to URL Groups
    my %tags;
    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        next if ! ( $obj->{type} eq 'lsl_tag' && $obj->{class} eq 'http' );
        my $full_name = escape_html($obj->{data}->{name});
        my $trunc_name = trunc($full_name, 30);
        $tags{$name}->{name} = $full_name;
        $tags{$name}->{trunc_name} = $trunc_name;
        $tags{$name}->{type} = "tag";
        $tags{$name}->{urls} ||= [];
    }
    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        next if ! ( $obj->{type} eq 'local_site' && $obj->{class} eq 'http' );
        next if ! @{ $obj->{data}->{tags} }; #If there are no tags, we skip the site

        my $url = $obj->{data}->{site};
        next if ($url =~ /[^a-zA-Z0-9.-]/); #SFOS doesn't support regex or CIDRs in URL Groups, so we can't import it

        foreach my $tag_ref (@{ $obj->{data}->{tags} }) {
            push @{ $tags{$tag_ref}->{urls} } , { url => $url };
        }
    }
    foreach my $key (keys %tags) {
        if (@{ $tags{$key}->{urls} } > 128) { #URL Group is too big, need to split
            my $loop = 1;
            while (my @list = splice(@{ $tags{$key}->{urls} }, 0, 128)) {
                push @ret, {
                    name => $tags{$key}->{name},
                    trunc_name => $tags{$key}->{trunc_name}." $loop",
                    type => $tags{$key}->{type},
                    urls => \@list
                };
                $loop++;
            }
        } else {
            push @ret, {
                name => $tags{$key}->{name},
                trunc_name => $tags{$key}->{trunc_name},
                type => $tags{$key}->{type},
                urls => \@{ $tags{$key}->{urls} }
            };
        }
    }

    $template->param(urlgroups => \@ret);
}

sub is_any_network {
    my ($network_obj) = @_;
    if ($network_obj->{data}->{resolved}) {
        if ($network_obj->{data}->{address} eq '0.0.0.0' 
                and $network_obj->{data}->{netmask} == 0) {
            say $network_obj->{data}->{name};
            return 1;
        }
    }
    if ($network_obj->{data}->{resolved6}) {
        if ($network_obj->{data}->{address6} eq '::' 
                and $network_obj->{data}->{netmask6} == 0) {
            say $network_obj->{data}->{name};
            return 1;
        }
    }
    return 0;
}

sub network_name {
    my ($network_obj) = @_;
    my $host = @{ parse_one_host $network_obj }[0];
    return { name => $host->{name} };
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
        return undef;
    }

    my $local_subnets = [ 
        map { network_name get_ref($backup, $_) } @{$obj->{data}->{networks}}
    ];

    my $remote_networks = [
        map { network_name get_ref($backup, $_) } @{$remote_gateway->{data}->{networks}}
    ];

    my $auth_type;

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

sub parse_ipsec_vpn_connections {
    my ($backup) = @_;
    my @ret;

    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        if ($obj->{class} eq 'ipsec_connection' and $obj->{type} eq 'site_to_site') {
            my $conn = parse_one_ipsec_vpn_connection $backup, $obj;
            push @ret, $conn if defined $conn;
        }
    }

    \@ret
}

sub prepare_ssl_tunnel_access_settings {
    my ($template, $backup) = @_;

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
    $template->param(\%ret);
}

sub parse_one_ssl_vpn_server {
    my ($backup, $obj) = @_;

    my @any_networks = grep { 
        is_any_network get_ref($backup, $_)
    } @{$obj->{data}->{local_networks}}, @{$obj->{data}->{remote_networks}};

    if (@any_networks) {
        warn "SSL VPN connection $obj->{data}->{name} can't use Any networks - found: @any_networks";
        return undef;
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

sub parse_ssl_vpn_servers {
    my ($backup) = @_;
    my @ret = ();

    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        if ($obj->{class} eq 'ssl_vpn' and $obj->{type} eq 'server_connection') {
            my $data = parse_one_ssl_vpn_server ($backup, $obj);
            push @ret, $data if defined $data;
        }
    }
    \@ret
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

    my $client_config = {
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
    $client_config
}

sub parse_ssl_vpn_clients {
    my ($backup) = @_;
    my @ret = ();
    my %extra_data = ();
    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        if ($obj->{class} eq 'ssl_vpn' and $obj->{type} eq 'client_connection') {
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
            push @ret, $client;

            my $apc = make_ssl_vpn_client_config($backup, $obj);
            $extra_data{$apc_filename} = JSON->new->utf8->encode($apc);
        }
    }
    return(\@ret, \%extra_data);
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

sub parse_certificates {
    my ($backup) = @_;
    my @ret = ();
    my %ret_extra_data = ();
    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        if ($obj->{class} eq 'ca' and $obj->{type} eq 'host_key_cert') {
            my ($cert, $extra_data) = parse_one_certificate $backup, $obj;
            push @ret, $cert;
            %ret_extra_data = (
                %ret_extra_data,
                %$extra_data
            );
        }
    }
    return (\@ret, \%ret_extra_data);
}

sub parse_one_ipsec_vpn_profile {
    my ($obj) = @_;

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


    my $profile = {
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

    $profile
}

sub parse_ipsec_vpn_profiles {
    my ($backup) = @_;
    my @ret = ();

    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        if ($obj->{class} eq 'ipsec' and $obj->{type} eq 'policy') {
            my $profile = parse_one_ipsec_vpn_profile $obj;
            push @ret, $profile;
        }
    }

    \@ret
}

sub prepare_ipsec_vpn_profile {
    my ($template, $backup) = @_;
    my $profile = parse_ipsec_vpn_profiles $backup;
    $template->param(profile => $profile);
}

sub prepare_ipsec_vpn_connections {
    my ($template, $backup) = @_;
    my $ipsec = parse_ipsec_vpn_connections $backup;
    $template->param(ipsec => $ipsec);
}

sub prepare_ssl_vpn_servers {
    my ($template, $backup) = @_;
    my $ssl_vpn_servers = parse_ssl_vpn_servers $backup;
    $template->param(servers => $ssl_vpn_servers);
}

sub prepare_ssl_vpn_clients {
    my ($template, $backup) = @_;
    my ($ssl_vpn_clients, $client_config_data) = parse_ssl_vpn_clients $backup;
    $template->param(clients => $ssl_vpn_clients);
    $client_config_data
}

sub prepare_certificates {
    my ($template, $backup) = @_;
    my ($ssl_vpn_clients, $certs) = parse_certificates $backup;
    $template->param(certificates => $ssl_vpn_clients);
    $certs
}

sub fill_html_template {
    my ($template_name, $backup) = @_;
    my $proc_func = $TEMPLATE{$template_name};
    my $filename = $HTML_TEMPLATE_DIR . $template_name;
    my $extra_data;
    if (! -f $filename) {
        say STDERR "Warning: Expected template $filename is missing. Skipping.";
        return;
    }
    my $template = HTML::Template->new(
            filename => $filename,
            utf8     => 1,
            debug    => $DEBUG,
            die_on_bad_params => 0)
        or die "Template creation failed";
    if (defined $proc_func) {
        say STDERR "preparing data for $template_name" if $DEBUG;
        $extra_data = $proc_func->($template, $backup);
    } else {
        # fallback: pass the whole backup to template
        $template->param(objects => $backup);
    }
    return ($template->output, $extra_data);
}

sub make_entities {
    my ($backup, $templates) = @_;
    my %extra = ();
    my $entities = '';
    for my $t (@$templates) {
        my ($content, $extra_data_from_template) = fill_html_template $t, $backup;
        $entities .= $content;
        if ($extra_data_from_template) {
            $extra{$t} = $extra_data_from_template;
        }
    }
    return ($entities, \%extra);
}

sub make_export_tar {
    my ($backup, $output_file) = @_;
    my @templates = ('Header.tmpl', (map { $_->[0]} @TEMPLATE),  'Footer.tmpl');
    my ($entities, $extra_data) = make_entities($backup, \@templates);

    my $tar = Archive::Tar->new;
    $tar->add_data('Entities.xml', $entities);

    while (my ($filename, $content) = each %{ $extra_data->{'SiteToSiteClient.tmpl'} } ) {
        $tar->add_data('Files/ServerConfigurationFile/0/' . $filename, $content);
    }
    while (my ($filename, $content) = each %{ $extra_data->{'Certificate.tmpl'} } ) {
        $tar->add_data('Files/CertificateFile/0/' . $filename, $content);
    }
    $tar->write($output_file);
}

my $backup_path;
my $template_name;
my $output_file = "Export.tar";

sub main {
    my %opt;
    getopts('hdi:o:s:', \%opt);
    usage() if $opt{h};
    usage() if (defined $opt{i} && ($opt{i} eq "" || ! -f $opt{i}));
    usage() if (defined $opt{o} && $opt{o} eq "");
    usage() if (defined $opt{s} && $opt{s} eq "");
    $template_name = $opt{s} if (defined $opt{s});
    $output_file = $opt{o} if (defined $opt{o});
    $DEBUG = 1 if $opt{d};

    if ($opt{i}) {
        $backup_path = $opt{i};
    } else {
        #Generate current snapshot
        my $snapshot_name = `$CONFD snapshot_create`;
        $snapshot_name =~ s/\s+$//;
        $backup_path = "$SNAPSHOT_DIR$snapshot_name";
    }
    say STDERR "Using confd snapshot $backup_path";

    my $backup = read_backup $backup_path;
    say STDERR 'confd objects in backup: ', scalar keys %{ $backup->{objects} } if $DEBUG;

    if ($template_name) { #Dry run / testing single template output. Print to STDOUT
        binmode STDOUT, ':encoding(utf8)';
        my ($template, $extra_data) = fill_html_template $template_name, $backup;
        say $template;
        if ($extra_data) {
            say STDERR "extra data present: ";
            say STDERR $_ for keys %$extra_data;
        }
    } else { #Full run. Print to $output_file
        say STDERR "Exporting objects from $backup_path to $output_file";
        make_export_tar $backup, $output_file;
        say STDERR "Export complete"
    }
}

__PACKAGE__->main(@ARGV) unless caller();
