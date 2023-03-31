#!/usr/bin/perl
#Copyright Sophos Ltd 2023
#
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use strict;
use warnings;
use v5.10.1;

use Getopt::Std;
use Storable;
use HTML::Template;
use Archive::Tar;

my $VERSION = '0.2';
# Sophos Migration Utility - CLI
# Compatible with UTM 9.7xx to SFOS 19.5.1
#
# Known issues / limitations:
#   - Tag and FilterAction List Website -> URL Group export
#       - Regexes are not exported (SFOS restriction)
#       - CIDR URLs are not exported (SFOS restriction)
#       - URLs containing paths are not exported (SFOS restriction)
#       - UTM's "include subdomains" is ignored. URL Groups always include subdomains on SFOS
#       - SFOS only allows 128 URLs per group. This tool will split them and create multple URL Groups when necessary.
#   - SFOS generally allows shorter names for objects than UTM. Names are truncated where necessary.
#   - DNS Groups -> IPLists is disabled - See DNSGrouptoIPLIST in sub parse_hosts() to re-enable
#   - Gateway hosts -> Gateways only supports IPv4 (SFOS restriction)
#
# Supported exports:
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
#
# Unsupported exports to be considered:
#   - VPN Settings
#   - Routes
#   - VLANs
#   - Firewall rules

my $DEBUG = 0;
my $CONFD = "/usr/local/bin/confd-client.plx";
my $SNAPSHOT_DIR = "/var/confd/var/storage/snapshots/";
my $HTML_TEMPLATE_DIR = './tmpl/';

use lib q/./;
use Protocols qw/$IP_PROTOS $ICMP4 $ICMP6/;

my %SERVICE_TYPE_MAP = ( tcp => 'TCPorUDP', udp => 'TCPorUDP', tcpudp => 'TCPorUDP', ip => 'IP', icmp => 'ICMP', icmpv6 => 'ICMPv6' );

my %TEMPLATE = (
    'Host.tmpl' => \&prepare_hosts,
    'GatewayHost.tmpl' => \&prepare_gatewayhost,
    'Services.tmpl' => \&prepare_services,
    'URLGroup.tmpl' => \&prepare_urlgroup,
    # ...
);

sub usage {
    say STDERR "Sophos Migration Utility CLI for UTM to SFOS - Version $VERSION";
    say STDERR "USAGE: $0 [-i path/to/snapshot] [-o path/to/Export.tar] [-d]";
    say STDERR "\t-i\t- Path to a specific UTM snapshot to be exported.\n\t\t  Usually located in /var/confd/var/storage/snapshots/";
    say STDERR "\t\t  If -i is not specified, a snapshot of the current UTM configuration will be created and used.";
    say STDERR "\t-o\t- Optional export path for the SFOS compatible TAR file.\n\t\t  Default: ./Export.tar";
    say STDERR "\t-d\t- Optional flag to enable debug output\n\t\t  Default: off";
    say STDERR "\t-s\t- Optional path to only export a single template type. For development purposes only.";
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

sub parse_hosts {
    my ($backup) = @_;
    my @ret = ();
    while (my ($name, $obj) = each %{ $backup->{objects} }) {
        next unless $obj->{class} eq 'network';
        next if ($obj->{type} eq 'group' ||
                 $obj->{type} eq 'multicast' ||
                 $obj->{type} eq 'availability_group');

        for ($obj->{type}) {
            if ($_ eq 'dns_host') {
                push @ret, {
                    name => sani_trunc("DNS Host: ".$obj->{data}->{name}),
                    type => 'FQDN',
                    address => $obj->{data}->{hostname}
                };

                if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && $obj->{data}->{address} ne "0.0.0.0") {
                    #DNS Host is resolved, create an IP Host
                    push @ret, {
                        name => sani_trunc("DNS Host IP: ".$obj->{data}->{name}),
                        type => 'IP',
                        family => 'IPv4',
                        address => $obj->{data}->{address}
                    };
                }

                if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && $obj->{data}->{address6} ne "::") {
                    push @ret, {
                        name => sani_trunc("DNS Host IPv6: ".$obj->{data}->{name}),
                        type => 'IP',
                        family => 'IPv6',
                        address => $obj->{data}->{address6}
                    };
                }
            } elsif ($_ eq 'host') {
                if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && $obj->{data}->{address} ne "0.0.0.0") {
                    push @ret, {
                        name => sani_trunc("Host IP: ".$obj->{data}->{name}),
                        type => 'IP',
                        family => 'IPv4',
                        address => $obj->{data}->{address}
                    };
                }

                if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && $obj->{data}->{address6} ne "::") {
                    push @ret, {
                        name => sani_trunc("Host IPv6: ".$obj->{data}->{name}),
                        type => 'IP',
                        family => 'IPv6',
                        address => $obj->{data}->{address6}
                    };
                }

                my @hostnames = @{ $obj->{data}->{hostnames} };
                my $i = 1;
                foreach my $hostname (@hostnames) {
                    push @ret, {
                        name => "IP Host DNS: " . sani_trunc($obj->{data}->{name}, 40) . " $i",
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
                        name => sani_trunc("IP Host MACs: ".$obj->{data}->{name}),
                        type => 'MACList',
                        macs => \@macs
                    };
                }
            } elsif ($_ eq 'network') {
                if ($obj->{data}->{address} && $obj->{data}->{address} ne "" && $obj->{data}->{address} ne "0.0.0.0") {
                    push @ret, {
                        name => sani_trunc("Network: ".$obj->{data}->{name}),
                        type => 'Network',
                        family => 'IPv4',
                        address => $obj->{data}->{address},
                        subnet => cidr_to_netmask($obj->{data}->{netmask})
                    };
                }
                if ($obj->{data}->{address6} && $obj->{data}->{address6} ne "" && $obj->{data}->{address6} ne "::") {
                    push @ret, {
                        name => sani_trunc("Network IPv6: ".$obj->{data}->{name}),
                        type => 'Network',
                        family => 'IPv6',
                        address => $obj->{data}->{address6},
                        subnet => $obj->{data}->{netmask6}
                    };
                }
            } elsif ($_ eq 'range') {
                if ($obj->{data}->{from} && $obj->{data}->{from} ne "") {
                    push @ret, {
                        name => sani_trunc("Range: ".$obj->{data}->{name}),
                        type => 'Range',
                        family => 'IPv4',
                        start_address => $obj->{data}->{from},
                        end_address => $obj->{data}->{to}
                    };
                }
                if ($obj->{data}->{from6} && $obj->{data}->{from6} ne "") {
                    push @ret, {
                        name => sani_trunc("Range IPv6: ".$obj->{data}->{name}),
                        type => 'Range',
                        family => 'IPv6',
                        start_address => $obj->{data}->{from6},
                        end_address => $obj->{data}->{to6}
                    };
                }
            } elsif ($_ eq 'dns_group') {

                push @ret, {
                    name => sani_trunc("DNS Group FQDN: ".$obj->{data}->{name}),
                    type => 'FQDN',
                    address => $obj->{data}->{hostname}
                };
                # DNSGrouptoIPLIST: Uncomment this section to enable export of resolved DNS Group IPs to an IPList in SFOS
                #my @addresses = @{ $obj->{data}->{addresses} };
                #if (@addresses) {
                #    push @ret, {
                #        name => sani_trunc("DNS Group: ".$obj->{data}->{hostname}),
                #        type => 'IPList',
                #        family => 'IPv4',
                #        addresses => join(',', @addresses)
                #    };
                #}
                #
                #my @addresses6 = @{ $obj->{data}->{addresses} };
                #if (@addresses6) {
                #    push @ret, {
                #        name => sani_trunc("DNS Group IPv6: ".$obj->{data}->{hostname}),
                #        type => 'IPList',
                #        family => 'IPv6',
                #        addresses => join(',', @addresses6)
                #    };
                #}
            }
        }
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
            comment => sanitize($obj->{data}->{comment}),
            src => get_ref($backup, $obj->{data}->{source})->{address},
            # src_display =>
            dest => get_ref($backup, $obj->{data}->{destination})->{name}, # todo why not address?
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
        name => sani_trunc($data->{name}),
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

sub sanitize {
    $_ = shift;
    return "" if (!defined $_ || $_ eq "");
    s/&/&amp;/g;
    s/</&lt;/g;
    s/>/&gt;/g;
    s/"/&quot;/g;
    return $_;
}

sub trunc {
    my $s  = shift;
    my $len = shift || 50;
    return "" if (!defined $s || $s eq "");
    return substr($s, 0, $len);
}

sub sani_trunc {
    my $s = shift;
    my $len = shift || 50;
    return "" if (!defined $s || $s eq "");
    $s = sanitize($s);
    $s = trunc($s,$len);
    return $s;
}

sub prepare_gatewayhost {
    my ($template, $backup) = @_;
    my @ret;

    my $interfaces = parse_interfaces $backup;
    my $routes = parse_routes $backup;

    for my $i (@$interfaces) {
        push @ret, {
            name => sani_trunc($i->{default_gw}), #TODO: Use generated name if empty
            gateway_ip => $i->{default_gw}
        }
    }

    for my $r (@$routes) {
        push @ret, {
            name => sani_trunc($r->{gateway}), #TODO: Use generated name if empty
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

        my $full_name = sanitize($obj->{data}->{name});
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
        my $full_name = sanitize($obj->{data}->{name});
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

sub fill_html_template {
    my ($template_name, $backup) = @_;
    my $proc_func = $TEMPLATE{$template_name};
    my $filename = $HTML_TEMPLATE_DIR . $template_name;
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
        $proc_func->($template, $backup);
    } else {
        # fallback
        $template->param(objects => $backup);
    }
    $template->output
}

my $backup_path;
my $template_name;
my $output_file = "Export.tar";
my $entities_fn = "Entities.xml";

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
say "Using confd snapshot $backup_path";

my $backup = read_backup $backup_path;
say STDERR 'confd objects in backup: ', scalar keys %{ $backup->{objects} } if $DEBUG;

binmode STDOUT, ':encoding(utf8)';

if ($template_name) { #Dry run / testing single template output. Print to STDOUT
    say fill_html_template $template_name, $backup;
} else { #Full run. Print to $output_file
    say "Exporting objects from $backup_path to $output_file";
    open my $FH, ">:encoding(UTF-8)", $entities_fn or die $!;
    print $FH fill_html_template "Header.tmpl";
    for my $template_name (sort keys %TEMPLATE) {
        print $FH fill_html_template $template_name, $backup;
    }
    print $FH fill_html_template "Footer.tmpl";
    close $FH or die $!;
    say "Exporting to $entities_fn";
    say "Creating output file archive $output_file";
    Archive::Tar->create_archive($output_file, "", ($entities_fn));
    say "Export complete"
}

