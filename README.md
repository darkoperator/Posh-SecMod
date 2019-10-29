# Posh-SecModule

This module is a PowerShell v3 only module at the moment. The module is a collection of functions that I have found usefull in my day to day work as a security professional. The functions are broken in to functionality:

- Discovery: Perform network discovery.
- Parse: Parsers for Nmap, DNSRecon and other type of output files from security tools.
- PostExploitation: Functions to help in performing post exploitation tasks.
- Registry: Collection of functions for manipulating the registry in remote hosts using WMI.
- Utilities: General purpose functions.
- Audit: Functions that may be usful when performing audits of systems.
- Database: Functions that are useful when interacting with databases.

## ChangeLog

### Version 1.3

Moved Nessus, Shodan, VirusTotal and Metasploit modules to individual ones for easier maintenance and update.

### Version 1.2

- Added Shodan submodule
- Added VirusTotal submodule
- Added Metasploit submodule
- BugFixes
- Added new fuctions in audit that work in WinPE for performing incident response and auditing (Disk MSFT Time, ADSI functions)


## Licensing

The functions I have written are BSD 3-Clause Licensed. The other files I used for the project are licensed as follows: 

- NessusSharp and Metasploit-Sharp libraries from Brandon Perry from: https://github.com/brandonprry are BSD 3-Clause Licensed.

- SQlite Libraries provided by the SQLite Projects these libraries are GPL2 licensed libraries.

- ARSoft.Tools.Net that is licensed ad Apache License 2.0 (Apache) http://arsofttoolsnet.codeplex.com/

- Whois Library from http://coderbuddy.wordpress.com/ under the GPL2 License

## Installation Instrcutions

To install the module from a PowerShell v3 session run:
<pre>
iex (New-Object Net.WebClient).DownloadString("https://gist.github.com/darkoperator/6404266/raw/982cae410fc41f6c64e69d91fc3dda777554f241/gistfile1.ps1")
</pre>
