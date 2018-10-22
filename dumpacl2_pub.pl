# written by Denis Kovyazin, kovyazinda@gmail.com

# Access rights dumping, doesn't work correctly with Deny ACLs (not displayed)
# List ACE are equal to Read ACE - see in Properties -> Security -> Advanced.
# List applies only to directory and subdirectory level, while Read applies to
# directories, subdirectories and files. To resolve this, script is checking
# only files (but puts their names as directories in report) - list ACE will
# not appear at all

# Reads target directory from STDIN, generates report aclrepYYYYMMDD.htm
# Persons, approving paths of shared area are passed through the section 
# Shared area owners - for report owner.


use Win32::FileSecurity qw(Get EnumerateRights);
use Data::Compare;
use File::Find;
use Win32::File;
use List::MoreUtils qw(any all none notall true false firstidx first_index 
                           lastidx last_index insert_after insert_after_string 
                           apply after after_incl before before_incl indexes 
                           firstval first_value lastval last_value each_array
                           each_arrayref pairwise natatime mesh zip uniq minmax);

use Win32::OLE;
use Win32::LongPath;
$Win32::OLE::Warn = 3;

#Shared area owners - for report file only


# Command line options
# Directory to check - argument 0
$inputpath=@ARGV[0];
# Debug enabled - argument 1
$usedebug=@ARGV[1];
# Account name resolution enabled - argument 2, domain name - argument 3
$useresolve=@ARGV[2];
$mydomain=@ARGV[3];

#values used globally by procedures
my %lasthash;
my $i;
my @aclarray,@uniqaclarray;

my $dirname,$displayname;

# Convert domain name from FQDN to canonical form
sub domain_name_convert
	{
	if ($mydomain)
		{
		$mydomain=~s/\./\,dc\=/g;
		$mydomain=~s/^/dc\=/;
		}
	}
# Retrieve a list of accounts from AD, and maps a DisplayName to account
# Example from AD Cookbook from O'Reilly.
# Needs optimisation
sub get_AD_accounts($)
	{
	my ($myaccount)=@_;
# Connecting to AD
	$myaccount=~s/^.*\\//;
	my $objConn = Win32::OLE->CreateObject("ADODB.Connection");
	$objConn->{Provider} = "ADsDSOObject";
	$objConn->Open;
# LDAP query syntax: <LDAP://domain>;
# (logical opration(input parameter 1)(input parameter 2));
# Return field 1, Return field 2;Level to search - subtree is universal)
	my $objRS = $objConn->Execute("<LDAP://$mydomain>;(&(objectclass=user)(objectcategory=person));Name,DisplayName;subtree");
# Working with query as with object:
# Methods: MoveFirst - First record, MoveNext - Next record
# Properties: EOF - end of query(last record), 
# Fields(i)->Value - value of Fields by number i
	$objRS->MoveFirst;
	while (not $objRS->EOF) 
		{
		if ($objRS->Fields(0)->Value eq $myaccount) {$displayname=$objRS->Fields(1)->Value};
		$objRS->MoveNext;
# Debugging
#		print $mydomain,"\t",$myaccount,"\t",$displayname,"\n";
		}
	}


# Get ACL from path
sub get_acl($)
	{
# Getting permission to hash
# Here are some basic masks:
# Full = 		111110000000111111111
# Read = 		100100000000010101001
# Read (files) =	100100000000010001001
# Write = 		100100000000110111111
# Modify =		100110000000110111111
# Write+Delete =	100100000000110111011

	my ($filename) = @_;
# Uncommit this line if you have problems with some ACL
#	print $filename,"\n";

	if ($filename ne "") {Get( $filename, \%hash ) or print ""};

# Permission comparison
	$hash_equal = Compare(\%lasthash,\%hash);
	if ($hash_equal == 1)
#	if (%lasthash==%hash)
		{
#		print "\n $filename - Permissions match to upper level\n";
		}
	else
		{
		while( ($name, $mask) = each %hash ) 
			{
# Removing "CREATOR OWNER" and "NT AUTHORITY\SYSTEM" from reports because 
# CREATOR OWNER is a legimate user who has created a document and 
# it is not interesting from point of our auditing task
# NT AUTHORITY is a system account and normally has full access everywhere

			if ($name ne "CREATOR OWNER" and $name ne "NT AUTHORITY\\SYSTEM") 
				{
				if ($filename ne "") 
					{
#					$filename=~s/\\.+$//;
					$filename=~s/\//\\/g;
					$dirname=~s/\//\\/g;

#					print FH "<td>", $filename,"</td>"
					} 
#				print FH "<td>","$name","</td>";

				$bin = sprintf "%b",$mask;

# putting permissions to human friendly variant
				$permission = "";
				if ($bin eq "111110000000111111111") {$permission="F"}
				if ($bin eq "100100000000010101001") {$permission="R"}
                                if ($bin eq "100100000000010001001") {$permission="R"}
				if ($bin eq "100100000000110111111") {$permission="W"}
				if ($bin eq "100110000000111111011") {$permission="WD"}				
				if ($bin eq "100110000000110111111") {$permission="M"}
				if ($bin eq "100100000000110111011") {$permission="W"}

#Debugging - different permission sets
				if ($permission eq "") {$permission=$bin}

#				print FH "<td>","$permission","</td></tr>";

# new section for array (will be used in acl_uniq subroutine)

				if ($usedebug eq "-d")
					{
					if ($useresolve eq "-r") 
						{
						$displayname="";
						get_AD_accounts($name);
						if ($displayname ne "") 
							{
							@aclarray[$i]="<tr><td>".$filename."</td><td>".$displayname."</td><td>".$permission."</td></tr>";
							}
						else
							{
							@aclarray[$i]="<tr><td>".$filename."</td><td>".$name."</td><td>".$permission."</td></tr>";
							}
						}
					else    {@aclarray[$i]="<tr><td>".$filename."</td><td>".$name."</td><td>".$permission."</td></tr>"};
					}
						
				else
					{
					if ($useresolve eq "-r") 
						{
						$displayname="";
						get_AD_accounts($name);
						if ($displayname ne "") 
							{
							@aclarray[$i]="<tr><td>".$dirname."</td><td>".$displayname."</td><td>".$permission."</td></tr>";
							}
						else
							{
							@aclarray[$i]="<tr><td>".$dirname."</td><td>".$name."</td><td>".$permission."</td></tr>";
							}
						}
					else    {@aclarray[$i]="<tr><td>".$filename."</td><td>".$name."</td><td>".$permission."</td></tr>"};
					}
# debug for acl array
#				print $i,"\t",@aclarray[$i],"\n";
				$i++;
				}              
			}
		%lasthash = %hash;
		}
	}



# Recursion of input path
sub getdir($)
        {
#	$fullpath=$File::Find::dir."/".$_;
#	print "Dir:$File::Find::dir\t","File::$File::Find::name\n";
	$fullpath=$File::Find::name;
#	$fullpath=$File::Find::dir."/".$_;
	$dirname=$File::Find::dir;


	Win32::File::GetAttributes($fullpath, $attrib);
	if ($attrib & DIRECTORY) 
		{
#		print "Directory $fullpath - skipped\n"
		}
		else
		{
# for debugging
#	eval {get_acl($fullpath) or print "ACL match for $fullpath\n"};
		if ($usedebug eq "-d") {print $fullpath,"\n"};
		eval {get_acl($fullpath) or print ""};
		}
        }


#form html header: info, legend, approvals
sub form_html_header
	{
# Current date/time transformation
	($cur_sec,$cur_min,$cur_hour,$cur_mday,$cur_mon,$cur_year,$cur_wday,$cur_yday,$cur_isdst) = localtime(time);
	$cur_year = sprintf("%02d", $cur_year % 100);

# Human names of months
	@abbr = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );

# Preparing file for writing
	$outputfilename="aclrep"."20".$cur_year.@abbr[$cur_mon].".htm";
	
# Creating HTML structure
	if ($inputpath ne "") 
		{
		open FH, ">$outputfilename" or die "Cannot write to file $outputfilename";
		print FH "<HTML>\n";
		print FH '<link rel="stylesheet" type="text/css" href="/akbv_user.css" />';
		print FH "<BODY>\n";
		print FH '<meta http-equiv="Content-Type" content="text/html; charset=windows-1251">',"\n";
# General section
		print FH "<font size=\"4\">\n";
       	
#Legend section
		print FH "<BR>Legend<BR>\n";
		print FH "<table border=1 cellspacing=\"0\" cellpadding=\"0\">\n";
		print FH "<tr>\n";
		print FH "<td><font size=\"4\">Access type</font></td>\n";
		print FH "<td><font size=\"4\">Description</font></td>\n";
		print FH "</tr>\n";
		print FH "<tr>\n";
		print FH "<td>R</td>\n";
		print FH "<td>Reading content of files</td>\n";
		print FH "</tr>\n";
		print FH "<tr>\n";
		print FH "<td>W</td>\n";
		print FH "<td>Creating new files (without modification of old ones)</td>\n";
		print FH "</tr>\n";
		print FH "<tr>\n";
		print FH "<td>M</td>\n";
		print FH "<td>Modificating and deleting of files</td>\n";
		print FH "</tr>\n";
		print FH "<tr>\n";
		print FH "<td>WD</td>\n";
		print FH "<td>Writing and deleting of files without modifying</td>\n";
		print FH "</tr>\n";
		print FH "<tr>\n";
		print FH "<td>F</td>\n";
		print FH "<td>Full access (including access control)</td>\n";
		print FH "</tr>\n";
		print FH "</table>\n";
		print FH "<BR><BR>\n";




       	
# Generated report section

		print FH "Path checked: ",$inputpath,"<BR><BR>\n";
		}
	else
		{
		print "No path specified!\n";
		print "Usage: perl dumpacl2.pl <path> [-d/-n] [-r dns-domain-name]\n";
		print "EXAMPLE: perl dumpacl2.pl C:\\\n";
		print "Use option -d to enable debugging - in this case filenames with\n";
		print "different permissions will be displayed instead of path where anomaly\n";
		print "has occurred. Use option -n to display path only.\n";
		print "Use option -r to enable account name resolution. Replace dns-domain-name\n";
		print "with name of desired domain, for example -r my.domain.local\n";
		die;
		}
	}

sub form_html_trailer
	{
	print FH "</table>\n";
	print FH "</BODY>\n";
	print FH "</HTML>\n";
	}

# Removes duplicate elements from acl list
sub acl_uniq
	{
	my $j;
	@uniqaclarray=uniq @aclarray;
	print FH "</table>\n";
	print FH "<table border=1 cellspacing=\"0\" cellpadding=\"0\">\n";
	print FH "<tr>\n";
	print FH "<td><font size=\"4\">Path</font></td>\n";
	print FH "<td><font size=\"4\">Account</font></td>\n";
	print FH "<td><font size=\"4\">Access type</font></td>\n";
	print FH "</tr>\n";
	print FH @uniqaclarray;
	}

#Calling procedure for domain name conversion
if ($useresolve eq "-r") {domain_name_convert()};

# Calling procedure for structure creation
form_html_header();

# Starting the recursion
find (\&getdir, $inputpath) or print "Done, check $outputfilename in current directory\n";

# Calling procedure for removing duplicates
acl_uniq();

# Creating the trailer of the file
form_html_trailer();