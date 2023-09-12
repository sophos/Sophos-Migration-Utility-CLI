package Protocols;
#Copyright Sophos Ltd 2023
#
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use strict;
use warnings;

our $VERSION = '0.1';

use Exporter 'import';
our @EXPORT = qw/$IP_PROTOS $ICMP4 $ICMP6/;

our $IP_PROTOS = { qw( 0 HOPOPT 1 ICMP 2 IGMP 3 GGP 4 IP 5 ST 6 TCP 7 CBT 8 EGP 9 IGP 10 BBN-RCC-MON 11 NVP-II
12 PUP 13 ARGUS 14 EMCON 15 XNET 16 CHAOS 17 UDP 18 MUX 19 DCN-MEAS 20 HMP 21 PRM 22 XNS-IDP 23 TRUNK-1
24 TRUNK-2 25 LEAF-1 26 LEAF-2 27 RDP 28 IRTP 29 ISO-TP4 30 NETBLT 31 MFE-NSP 32 MERIT-INP 33 DCCP 34 3PC
35 IDPR 36 XTP 37 DDP 38 IDPR-CMTP 39 TP++ 40 IL 41 IPv6 42 SDRP 43 IPv6-Route 44 IPv6-Frag 45 IDRP 46 RSVP
47 GRE 48 DSR 49 BNA 50 ESP 51 AH 52 I-NLSP 53 SWIPE 54 NARP 55 MOBILE 56 TLSP 57 SKIP 58 ICMPv6 59 IPv6-NoNxt
60 IPv6-Opts 62 CFTP 64 SAT-EXPAK 65 KRYPTOLAN 66 RVD 67 IPPC 69 SAT-MON 70 VISA 71 IPCV 72 CPNX 73 CPHB
74 WSN 75 PVP 76 BR-SAT-MON 77 SUN-ND 78 WB-MON 79 WB-EXPAK 80 ISO-IP 81 VMTP 82 SECURE-VMTP 83 VINES 84 TTP
85 NSFNET-IGP 86 DGP 87 TCF 88 EIGRP 89 OSPFIGP 90 Sprite-RPC 91 LARP 92 MTP 93 AX 94 IPIP 95 MICP 96 SCC-SP
97 ETHERIP 98 ENCAP 100 GMTP 101 IFMP 102 PNNI 103 PIM 104 ARIS 105 SCPS 106 QNX 107 A/N 108 IPComp 109 SNP
110 Compaq-Peer 111 IPX-in-IP 112 VRRP 113 PGM 115 L2TP 116 DDX 117 IATP 118 STP 119 SRP 120 UTI 121 SMP
122 SM 123 PTP 124 ISIS 125 FIRE 126 CRTP 127 CRUDP 128 SSCOPMCE 129 IPLT 130 SPS 131 PIPE 132 SCTP 133 FC
134 RSVP-E2E-IGNORE 136 UDPLite 137 MPLS-in-IP 138 manet 139 HIP 140 Shim6 141 WESP 142 ROHC ) };

for (my $i = 0; $i <= 255; $i++) {
	$IP_PROTOS->{$i} = "IPProto$i" if ! $IP_PROTOS->{$i};
}

#Note: There are some spelling errors, whitespace errors, and capitalization inconsistencies in these definitions.
#      They are on purpose, as these are the exact strings SFOS is expecting for import.
#      Modifying them will break the import of that service.
our $ICMP4 = {
	0  => { name => "Echo Reply", 0 => "No Code" },
	3  => { name => "Destination Unreachable",
		0 => "Hop Limit Exceeded In Transit", 1 => "Host Unreachable", 2 => "Protocol Unreachable",
		3 => "Port Unreachable", 4 => "Fragmentation Needed and Don't Fragment was Set",
		5 => "Source Route Failed", 6 => "Destination Network Unknown", 7 => "Destination Host Unknown",
		8 => "Source Host Isolated", 9 => "Communication with Destination Network is Administratively Prohibited",
		10 => "Communication with Destination Host is Administratively Prohibited",
		11 => "Destination Network Unreachable for Type of Service",
		12 => "Destination Host Unreachable for Type ofService", 13 => "Communication Administratively Prohibited",
		14 => "Host Precedence Violation", 15 => "Precedence cutoff in effect"
		},
	4  => { name => "Source Quench", 0 => "Erroneous Header Field Encountered"},
	5  => { name => "Redirect",
		0 => "Redirect Datagram for the Network (or subnet)", 1 => "Redirect Datagram for the Host",
		2 => "Redirect Datagram for the Type of Service and Network", 3 => "Redirect Datagram for the Type of Service and Host"
		},
	6  => { name => "Alternate Host Address", 0 => "Alternate Address for Host" },
	8  => { name => "Echo", 0 => "No Code" },
	9  => { name => "Router Advertisement", 0 => "No Code", 16 => "Any code" }, #16 has no direct mapping
	10 => { name => "Router Selection", 0 => "No Code" },
	11 => { name => "Time Exceeded", 0 => "Time to Live exceeded in Transit", 1 => "Fragement Reassembly Time Exceeded" },
	12 => { name => "Parameter Problem", 0 => "Pointer indicates the error", 1 => "Missing a Required Option", 2 => "Bad Length" },
	13 => { name => "Timestamp", 0 => "No Code" },
	14 => { name => "Timestamp Reply", 0 => "No Code" },
	15 => { name => "Information Request", 0 => "No Code" },
	16 => { name => "Information Reply", 0 => "No Code" },
	17 => { name => "Address Mask Request", 0 => "No Code" },
	18 => { name => "Address Mask Reply", 0 => "No Code" },
	30 => { name => "Traceroute", 0 => "No Code" },
	31 => { name => "Datagram Conversion Error", 0 => "No Code" },
	32 => { name => "Mobile Host Redirect", 0 => "No Code" },
	33 => { name => "IPv6 Where-Are-You", 0 => "No Code" },
	34 => { name => "IPv6 I-Am-Here", 0 => "No Code" },
	35 => { name => "Mobile Registration Request", 0 => "No Code" },
	36 => { name => "Mobile Registration Reply", 0 => "No Code" },
	39 => { name => "SKIP", 0 => "No Code" },
	40 => { name => "Photuris", 0 => "Any code", 1 => "Any code", 2 => "Any code", 3 => "Any code", 4 => "Any code", 5 => "Any code" } #No direct mapping for any codes
};

our $ICMP6 = {
	1  	=> { name => "Destination Unreachable",
		0 => "No Route To Destination", 1 => "Communication With Destination Administratively Prohibited", 2 => "Beyond Scope Of Source Address",
		3 => "Address Unreachable", 4 => "Port Unreachable", 5 => "Source Address Failed Ingress/Egress Policy", 6 => "Reject Route To Destination"
		},
	2  	=> { name => "Packet Too Big", 0 => "No Code"},
	3  	=> { name => "Time Exceeded", 0 => "Hop Limit Exceeded In Transit", 1 => "Host Unreachable" },
	4  	=> { name => "Parameter Problem", 0 => "Erroneous Header Field Encountered", 1 => "Unrecognized Next Header Type Encountered",
		2 => "Unrecognized IPv6 Option Encountered"
		},
	128 => { name => "Echo Request", 0 => "No Code" },
	129 => { name => "Echo Reply", 0 => "No Code" },
	130 => { name => "Multicast Listener Query", 0 => "No Code" },
	131 => { name => "Multicast Listener Report", 0 => "No Code" },
	132 => { name => "Multicast Listener Done", 0 => "No Code" },
	133 => { name => "Router Solicitation", 0 => "No Code" },
	134 => { name => "Router Advertisement", 0 => "No Code" },
	135 => { name => "Neighbor Solicitation", 0 => "No Code" },
	136 => { name => "Neighbor Advertisement", 0 => "No Code" },
	137 => { name => "Redirect Message", 0 => "No Code" },
	138 => { name => "Router Renumbering", 0 => "Router Renumbering Command", 1 => "Router Renumbering Result", 255 => "Sequence Number Reset" },
	139 => { name => "ICMP Node Information Query", 0 => "The Data Field Contains An IPv6 Address Which Is The Subject Of This Query.",
		1 => "The Data Field Contains A Name Which Is The Subject Of This Query, Or Is Empty, As In The Case Of A NOOP.",
		2 => "The Data Field Contains An IPv4 Address Which Is The Subject Of This Query."
		},
	140 => { name => "ICMP Node Information Response", 0 => "A Successful Reply.  The Reply Data Field May Or May Not Be Empty.",
		1 => "The Responder Refuses To Supply The Answer.  The Reply Data Field Will Be Empty.",
		2 => "The Qtype Of The Query Is Unknown To The Responder.  The Reply Data Field Will Be Empty."
		},
	141 => { name => "Inverse Neighbour Discovery Solicitation Message", 0 => "No Code" },
	142 => { name => "Inverse Neighbour Discovery Advertisement Message", 0 => "No Code" },
	143 => { name => "Version 2 Multicast Listener Report" },
	144 => { name => "Home Agent Address Discovery Request Message", 0 => "No Code" },
	145 => { name => "Home Agent Address Discovery Reply Message", 0 => "No Code" },
	146 => { name => "Mobile Prefix Solicitation", 0 => "No Code" },
	147 => { name => "Mobile Prefix Advertisement", 0 => "Any code" }, #UTM's 0 maps to "Any code" here
	151 => { name => "Multicast Router Advertisement" },
	152 => { name => "Multicast Router Solicitation" },
	153 => { name => "Multicast Router Termination" },
	154 => { name => "FMIPv6 Messages" }
};

1;