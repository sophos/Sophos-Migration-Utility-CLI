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

## Copyright and License
Copyright Sophos Ltd 2023

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
