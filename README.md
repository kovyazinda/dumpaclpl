# dumpaclpl
Perl NTFS ACL dump and compare

- Access rights dumping, doesn't work correctly with Deny ACLs (not displayed)
- List ACE are equal to Read ACE - see in Properties -> Security -> Advanced.
- List applies only to directory and subdirectory level, while Read applies to
  directories, subdirectories and files. To resolve this, script is checking
  only files (but puts their names as directories in report) - list ACE will
  not appear at all

- Reads target directory from STDIN, generates report aclrepYYYYMMDD.htm

- Requires to be run on Windows platform due to Win32 modules operation

# Prerequisites:
Install modules:

# CPAN:
Win32::FileSecurity
Data::Compare
File::Find
Win32::File
List::MoreUtils

# PPM:
Win32-FileSecurity
Data-Compare
File-Find
Win32-File
List-MoreUtils


# Usage: perl dumpacl2.pl <path> [-d/-n] [-r dns-domain-name]
		
EXAMPLE: perl dumpacl2.pl C:\
		
Use option -d to enable debugging - in this case filenames with different permissions will be displayed instead of path where anomaly has occurred. 
Use option -n to display path only.
Use option -r to enable account name resolution. Replace dns-domain-name with name of desired domain, for example -r my.domain.local
