# Sophos Migration Utility CLI

Tool for converting Sophos UTM configuration snapshots to an SFOS importable configuration archive.
The tool targets SFOS APIVersion `2105.1`.

## Installation
Extract all files to a directory on the target system. UTM will already have all required Perl modules installed.

## Usage
USAGE: ./migrate.pl [-i path/to/snapshot] [-o path/to/Export.tar] [args]

- -i - Path to a specific UTM snapshot to be exported. Usually located in /var/confd/var/storage/snapshots/. If -i is not specified, a snapshot of the current UTM configuration will be created and used.
- -o - Optional export path for the SFOS compatible TAR file. Default: ./Export.tar
- -d - Optional debug output; repeat for higher verbosity (`-dd` enables validation failure reasons). Default: off
- -s - Optional template name to only export a single template type to STDOUT (skips creating `Export.tar`). For development purposes only.
- -p - Optional SFOS interface name for VPN local interface defaults. Default: `Port1`
- -D - Optional SFOS interface name for DHCP fallback when source interface labels are not SFOS-compatible. Default: `Port1`
- -h - Display this help / usage message.
- -l - Optional flag to force-enable firewall-rule logging (`logtraffic=Enable`) for migrated rules. Default: follow source rule log setting.
- -F - Optional flag to disable migration of firewall rules. Default: off
- -I - Optional fallback interface name for static interface routes (e.g., `Port1`). Default: `Port1`. If not specified, interface routes use the default interface.
- -N - Optional NAT strategy mode (`safe` or `compat`). Default: `compat`
- -R - Optional path for migration report JSON. Default: `<output>.report.json`

Important: This tool is meant to be run on Sophos UTM / ASG systems. Usage on other systems may require you to convert the snapshot file (see util/convert_snapshot.pl), and will require the -i option.

Once you have generated the Export.tar file, copy it to a system with access to the SFOS device Web Admin. On the SFOS UI, navigate to "System" > "Backup & firmware" > "Import export". Choose the file to import, and click "Import". Your objects will be imported after some time.

### Examples
On a Sophos UTM, create a snapshot of the current configuration and export it to Export.tar
```
./migrate.pl
```

On a Sophos UTM, use a specific snapshot and export it to TestExport.tar
```
./migrate.pl -i /var/confd/var/storage/snapshots/cfg_11111_11111111 -o TestExport.tar
```

### Instructions for running on UTM
The following instructions are one way you can set up your Sophos UTM and run the migration utility on it directly

#### Set up Shell Access in the Sophos UTM
To turn on SSH access in Sophos UTM 9, do as follows:
1. Log in to the Sophos UTM WebAdmin.
2. Go to Management > System Settings > Shell Access.
3. Turn on SSH Shell Access.
4. Ensure you have working credentials to access the Sophos UTM over SSH.

**Note**: Sophos UTM allows only two shell accounts, loginuser, and root. If you use a username and password, you must first log in as the less privileged loginuser, then escalate to root privileges using the su command, and enter the root password when prompted. You may also use SSH keys if preferred. It's possible to allow direct login as the root user if you use an SSH key rather than a username and password. If you're unfamiliar with SSH keys, choose strong passwords for the loginuser and root accounts.
If you don't know the credentials, you can reset the loginuser and root passwords on the Shell Access page.

#### Migration Instructions
To migrate your settings, do as follows:
1. Access the migration utility at this link, where you can review its source and additional instructions for advanced use cases: https://github.com/sophos/Sophos-Migration-Utility-CLI.
2. Download the script and supporting files from https://github.com/sophos/Sophos-Migration-Utility-CLI/archive/refs/heads/master.zip to your computer.
3. Extract the downloaded zip file (Sophos-Migration-Utility-CLI-master.zip).
4. Use your preferred SCP utility, for example, WinSCP on Microsoft Windows, to transfer all extracted contents from the above download to your Sophos UTM's /home/login folder.
5. Authenticate with a username and password. Enter the username as loginuser and enter the password.
6. Once logged in as loginuser, enter the following command to switch to root permissions:
```
su -
<enter the root password>
```
**Note:** Alternatively, you can use root with SSH key authentication. To do this, enter the username as root

7. The uploaded files should be in a folder created in the /home/login/ folder. Make a note of the full path of the migrate.pl script. For this example, we'll assume it's in /home/login/Sophos-Migration-Utility-CLI-master/.
8. To run the migration, enter the following commands:
```
cd /home/login/Sophos-Migration-Utility-CLI-master/
perl migrate.pl
```

The output should look like this:
```
Using confd snapshot
/var/confd/var/storage/snapshots/cfg_17202_1680560553
Exporting objects from
/var/confd/var/storage/snapshots/cfg_17202_1680560553 to Export.tar
Exporting to Entities.xml
Creating output file archive Export.tar
Export complete
```

9. SCP copy the Export.tar file from /home/login/Sophos-Migration-Utility-CLI-master/ to your computer.
10. (Optional) SCP copy the Entities.xml file from the same location to your computer.
11. (Optional) Review the contents of the Entities.xml file to review what will be imported.
12. Log into the SFOS web admin console.
13. Go to Backup & firmware > Import export.
14. To import the Export.tar file, click Choose File, browse to where it's saved, then click Import.
**Note:** The import will progress in the background and may take a few minutes, depending on the size of the configuration.

15. To monitor the progress of the import, select Log Viewer at the top of the page, then select Admin from the drop-down list.
You will see objects and settings being imported, and once logs stop appearing, you can check to see that all expected configuration has been imported.
If the file was manually edited before importing, any formatting errors will appear in this log, which may help you troubleshoot any issues.


## Help
If you need assistance with migration, you can do as follows:

- Contact your local Sophos Partner
- Contact the Migration helpdesk
- Use the Community Forum, where we have a dedicated section for Lifecycle and Migration

## Known issues and limitations

1. Tag and FilterAction List Website -> URL Group export
    - Regexes are not exported (SFOS restriction)
    - CIDR URLs are not exported (SFOS restriction)
    - URLs containing paths are not exported (SFOS restriction)
    - UTM's "include subdomains" is ignored. URL Groups always include subdomains on SFOS
    - SFOS only allows 128 URLs per group. This tool will split them and create multiple URL Groups when necessary.
2. SFOS generally allows shorter names for objects than UTM. Names are truncated where necessary.
3. DNS Groups -> IPLists is disabled - See `DNSGrouptoIPLIST` in `parse_one_host_from_dns_group()` to re-enable.
4. Gateway hosts -> Gateways export is best-effort; IPv4/IPv6 projection depends on source data quality and resolvable address family.
5. UTM host static DNS hostnames are exported additively as DNSHostEntry records, while existing FQDNHost projection remains unchanged for policy compatibility.
6. UTM 'Any' semantic values (for networks, services, and protocols) are mapped by omitting tags in the exported XML, conforming to SFOS schema validation.
7. Data quality safeguards:
    - SSL VPN Site-to-Site uses exportable certificate resolution/fallback so missing/invalid certificate references do not break server-certificate emission.
    - DHCP drops empty secondary DNS values to avoid `0.0.0.0` import validation failures.
    - DHCP resolves interface names with best-effort UTM->SFOS mapping (`ethN` -> `PortN+1`) and falls back to the configured default SFOS interface (`-D`, default `Port1`) when source labels are not SFOS-compatible.
    - DHCP subnet context follows UTM semantics: non-relay servers derive subnet/IP context from bound `server.address` (or interface primary context), while relay-mode servers derive subnet mask from `server.netmask`.
    - DHCP lease timing aligns with UTM semantics: single `lease_time` (seconds) is converted to SFOS `DefaultLeaseTime` and `MaxLeaseTime` (minutes).
    - DHCP relay semantics align with UTM: `relay_mode` is exported to SFOS `LeaseForRelay`.
    - DHCP maps transferable server-scoped option data into SFOS `BootServer`/`BootFile` and `DHCPOption` fields where type/code projection is safe.
    - DHCP maps WINS server to `PrimaryWINSServer` when source node-type semantics permit (`wins_node_type > 1`).
    - DHCP emits explicit warnings for non-transferable UTM fields (`wins_node_type`, `deny_unknown`, `proxy_autoconfig`).
    - DHCP static lease hostnames are normalized to SFOS `dhcpHostname`-compatible values; each normalization/fallback is emitted as a migration warning with object context.
    - DHCP static lease hostnames that collide after normalization are deterministically de-collided per DHCP server (IP/ref-derived suffixing) so SFOS keeps hostname/mac/ip tuple cardinality intact.
    - DHCPv4 servers are always exported as disabled (`Status=0`) because SFOS import rejects many valid-in-UTM enabled combinations at import time.
    - DHCP subnet mismatches (lease range / gateway / static lease IP outside resolved interface subnet) are retained as warning signals while export continues in disabled mode.

    - IPv4 firewall source/destination export drops IPv6-only host/network/range candidates with explicit warnings to satisfy SFOS `sourceid`/`destinationid` family validation defaults.
    - Global UTM GEOIP (`main.geoip`) is exported as SFOS `CountryGroup` plus synthetic `FirewallRule` entities (exceptions first, then source/destination block rules). UTM ISO country codes are translated to SFOS country-host names (APIVersion 2105.1 baseline) with compatibility handling for deprecated codes (`AN` -> `BQ`,`CW`,`SX`); codes with no SFOS-compatible successor mapping (for example `BV`, `HM`) and unknown/unmapped codes are skipped with warnings while export continues. GEOIP exceptions that reference an Any-network object are exported as wildcard Any by omitting `SourceNetworks`/`DestinationNetworks` tags instead of being skipped.
    - Recurring overnight schedules are split into explicit per-day SFOS-valid carry rows (source day `start_time->23:59`, next day `00:00->stop_time`) so cross-midnight windows preserve weekday pairing; non-exportable schedule refs in web filter rules fall back to `All The Time`.
    - Host-type dispatch in `parse_one_host` now uses explicit function-call syntax for all `parse_one_host_from_*` branches (including standalone `mac_list/mac_list`) to avoid Perl indirect-object parsing ambiguity.
    - Deprecated UTM default Sophos LiveConnect hostname `all.broker.sophos.com` is blacklisted and skipped from Host/DNSHostEntry export to avoid emitting a known NXDOMAIN FQDN into SFOS.

8. SFOS validates the VPN connections more strictly than UTM.  Because of this, some configurations that are valid in UTM will be silently rejected by SFOS.
It is not feasible to reimplement all the SFOS validation rules, so this tool will only detect a limited number of issues that may cause problems, as mentioned below.  Please be advised there may be more situations that will cause SFOS to reject the settings.

    - Pre-shared key length must be at least 5 characters
    - VPN connections must have well defined networks - can't use "Any" as network definitions
    - X509 `from_certificate` VPN IDs now use guarded certificate/meta lookup, so missing refs do not emit Perl uninitialized warnings; invalid rows continue to be skipped by existing ID validation.
    - UTM certificate-derived `der_asn1_dn` VPN ID type is normalized to SFOS `DER ASN1 DN (X.509)` mapping.

9. This version will import the local ID (usually a hostname) from UTM into SFOS.
10. 7. Users and groups are not imported.  For VPN definitions, they have to be added manually.
11. Nested service and network groups are not imported, as they are not supported in SFOS.
12. Time export is server-driven: `Time` is emitted when `main.ntp.servers` contains exportable values even if `main.ntp.status` is disabled. `NTPServer` access-rule export remains status-driven and requires resolvable references in both `main.ntp.allowed_networks` and `main.ntp.servers` (`host`, `dns_host`, `dns_group`, `availability_group`); when multiple refs are present, destination selection prefers NAT-compatible host/network/range objects before FQDN-only projections. Literal server values are exported only to `Time` custom server settings.
13. NAT outbound interface export first applies best-effort UTM->SFOS mapping (`ethN` -> `PortN+1`), then falls back to `-I` (default `Port1`); unresolved references are skipped with warnings.
14. Template emission is metadata-driven (`%TEMPLATE_METADATA`). Legacy labels like `SophosConnection` were not wired to an active v0.8 export handler and are not part of generated output.

# Supported exports:
   - Web Filter Action Allow and Block lists -> URL Groups
   - Website tags -> URL Groups
   - TCP, UDP, and TCP/UDP Services -> TCPorUDP Services
   - Service Groups
   - ICMP Services -> ICMP Services
   - ICMPv6 Services -> ICMPv6 Services
   - IP Services -> IP Services (including ESP and AH)
   - Host Definitions -> FQDN Hosts, IP Hosts IPs (IPv4 and IPv6), MACs, and MAC Lists
   - Host static DNS mappings (`network/host.hostnames`) -> DNS Host Entry
   - Network Groups
   - Network Definitions -> IP Host Networks (IPv4 and IPv6)
   - IP Ranges -> IP Host Ranges (IPv4 and IPv6)
   - DNS Group hostname -> FQDNHost
   - Gateway Hosts -> Gateways (IPv4/IPv6 where resolvable)
   - Static Routes (`route/static`) -> UnicastRoute (gateway routes, interface routes via `-I` with default `Port1`, and blackhole routes with SFOS-safe `Distance=0`)
   - VPN Settings - site-to-site, SSL VPN remote access, and PPTP configuration
   - Time schedules (`time/recurring`, `time/single`) -> `Schedule` (including overnight recurring split normalization)
   - Firewall Rules (including DSCP marking from Mangle rules)
   - Global GEOIP policy (`main.geoip`) -> `CountryGroup` + synthetic `FirewallRule` chain (exception allow rules + source/destination block rules)
   - Application Control (`application_control/rule` -> `ApplicationFilterPolicy`)
   - ATP global settings, including host/network exceptions with interface-primary (`itfparams/primary`) fallback via `primary_address`, interface-network (`network/interface_network`) fallback via linked `interface_address`/primary references, unresolved-host-reference warnings, and best-effort threat exception normalization/filtering for SFOS-compatible import values
   - Time settings (`Time`) and status-gated NTP access policy bundle (`NTPServer`)
   - Web filter exceptions (`http/exception` -> `WebFilterException`) with skip-check projection for HTTPS decrypt/certificate validation, malware scan, zero-day protection, and policy checks; URL regex normalization preserves a leading `^` anchor while stripping `http(s)://` prefixes
   - Flood protection mapping (`flood_protection`) plus flood exclusions (`ips/exception` skiplist `tcp_flood|udp_flood|icmp_flood`) -> `DoSSettings` and `DoSBypassRules` (source/destination emitted as SFOS IPv4 literals or CIDR; PSD intentionally excluded)
   - NAT rules with optional firewall-for-NAT generation (`-N compat`), including Masquerading and Server Load Balancing, outbound interface projection, and explicit NATMethod/HealthCheck emission
  - DHCP static leases attached to DHCP server payload (IPv4 and IPv6), with UTM-aligned non-relay vs relay subnet derivation, `lease_time` seconds->minutes alignment, relay-mode to `LeaseForRelay` mapping, optional WINS/boot/DHCP option transfer where safely mappable, interface normalization fallback via `-D`, hostname normalization + collision-safe de-collision for SFOS `dhcpHostname` compatibility, and migrated DHCPv4 servers emitted disabled (`Status=0`) for import safety
   - HTTP proxy exception mapping only (`WebFilterException`)

## Migration report

Each full export writes a machine-readable report file (JSON) containing warnings and per-feature counters.  
Default output path is `<Export.tar>.report.json`, or provide `-R <path>` to override.

## AI Usage
Content co-created by Sophos and Cursor

## Copyright and License
Copyright Sophos Ltd 2026

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
