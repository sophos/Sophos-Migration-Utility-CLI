# Sophos Migration Utility CLI

Tool for converting Sophos UTM configuration snapshots to an SFOS 19.5.1+ importable configuration archive.

## Installation
Extract all files to a directory on the target system. UTM will already have all required Perl modules installed.

## Usage
USAGE: ./migrate.pl [-i path/to/snapshot] [-o path/to/Export.tar] [-d]

- -i - Path to a specific UTM snapshot to be exported. Usually located in /var/confd/var/storage/snapshots/. If -i is not specified, a snapshot of the current UTM configuration will be created and used.
- -o - Optional export path for the SFOS compatible TAR file. Default: ./Export.tar
- -d - Optional flag to enable debug output. Default: off
- -s - Optional path to only export a single template type. For development purposes only.
- -h - Display this help / usage message.

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

7. The uploaded files should be in a folder created in the /home/login/ folder. Make a note of the full path of the migrate.pl script. For this example, we'll assume it's in /home/login/sma.cli-master/.
8. To run the migration, enter the following commands:
```
cd /home/login/sma.cli-master/
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

9. SCP copy the Export.tar file from/home/login/sma.cli-master/ to your computer.
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
    - SFOS only allows 128 URLs per group. This tool will split them and create multple URL Groups when necessary.
2. SFOS generally allows shorter names for objects than UTM. Names are truncated where necessary.
3. DNS Groups -> IPLists is disabled - See DNSGrouptoIPLIST in sub parse_hosts() to re-enable
4. Gateway hosts -> Gateways only supports IPv4 (SFOS restriction)

5. SFOS validates the VPN connections more strictly than UTM.  Because of this, some configurations that are valid in UTM will be silently rejected by SFOS.  
It is not feasible to reimplement all the SFOS validation rules, so this tool will only detect a limited number of issues that may cause problems, as mentioned below.  Please be advised there may be more situations that will cause SFOS to reject the settings.

    - Pre-shared key length must be at least 5 characters
    - VPN connections must have well defined networks - can't use "Any" as network definitions

6. This version will import the local ID (usually a hostname) from UTM into SFOS.

# Supported exports:
   - Web Filter Action Allow and Block lists -> URL Groups
   - Website tags -> URL Groups
   - TCP, UDP, and TCP/UDP Services -> TCPorUDP Services
   - ICMP Services -> ICMP Services
   - ICMPv6 Services -> ICMPv6 Services
   - IP Services -> IP Services
   - Host Definitions -> FQDN Hosts, IP Hosts IPs (IPv4 and IPv6), and MACs
   - Network Definitions -> IP Host Networks (IPv4 and IPv6)
   - IP Ranges -> IP Host Ranges (IPv4 and IPv6)
   - DNS Group hostname -> FQDNHost
   - Gateway Hosts -> Gateways (IPv4)
   - VPN Settings - site-to-site only

# Unsupported exports to be considered:
   - VPN Settings - remote access
   - Routes
   - VLANs
   - Firewall rules

## Copyright and License
Copyright Sophos Ltd 2023

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
