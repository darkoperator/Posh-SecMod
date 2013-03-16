#Posh-SecModule
This module is a PowerShell v3 only module at the moment. The module is a collection of functions that I have found usefull in my day to day work as a security professional. The functions are broken in to functionality:

- Discovery: Perform network discovery.
- Parse: Parsers for Nmap, DNSRecon and other type of output files from security tools.
- PostExploitation: Functions to help in performing post exploitation tasks.
- Registry: Collection of functions for manipulating the registry in remote hosts using WMI.
- Nessus: Collection of assemblies and functions for automating the Nessus Vulnerability Scanner.
- Utilities: General purpose functions.
- Audit: Functions that may be usful when performing audit of systems.
- Database: Functions that are useful when interacting with databases.

The project is still in development and should be considered in a Alpha stage.

## Licensing
The functions I have written are BSD 3-Clause Licensed. The other files I used for the project are licensed as follows: 

- NessusSharp library from Brandon Perry from: https://github.com/brandonprry/nessus-sharp thos is BSD 3-Clause Licensed.

- SQlite Libraries provided by the SQLite Projects these libraries are GPL2 licensed libraries.

- ARSoft.Tools.Net that is licensed ad Apache License 2.0 (Apache) http://arsofttoolsnet.codeplex.com/

- Whois Library from http://coderbuddy.wordpress.com/ under the GPL2 License

## Installation Instrcutions

###Download and Install Git

Download the latest version of Git for Windows from http://msysgit.github.com/
When you install make sure of the following:

- Select **Run Git from the Windows Command Prompt** in the **Ajusting your PATH environment** step of the installation wizard.
- Select Checkout as-is and commit as-is in the options for formating.
 	
###Install Posh-Git using PsGet

Run PowerShell with elevetaed privelages and make sure that you have set the ExecutionPolicy to RemoteSigned since none of the scripts, binaries and modules are signed with authenticode. 
<pre>
Set-ExecutionPolicy RemoteSigned
</pre>

We will use the PS-Get utility to download and install Posh-Git, for this we first install PS-Get we do this by running in PowerShell:
<pre>
(new-object Net.WebClient).DownloadString("http://psget.net/GetPsGet.ps1") | iex
</pre>

Once installed we can now install Posh-Git by running:
<pre>
install-module posh-git
</pre>

Reload your profile to make sure everything is set to use Posh-Git by running:
<pre>
. $PROFILE
</pre>
If you get an error for SSH-Agent not being present do not worry since the checkout is done via web for the module. If you want to use SSH to do checkouts in GitHub and plan on using it you will have to append to your path in PowerShell the path to the executable. In PowerShell run:
<pre>
notepad $PROFILE
</pre>
Add to the begining of the file:
<pre>
$env:path += ";" + (Get-Item "Env:ProgramFiles(x86)").Value + "\Git\bin"
</pre>

and reload your profile by running:
<pre>
. $PROFILE
</pre>

###Install the Latest Development Version of Posh-SecMod

To download the latest version go to your profile module path from withing PowerShell:
<pre>
cd $env:PSModulePath.split(";")[0]
</pre>

Use git to clone the latest development version of the module:
<pre>
git clone https://github.com/darkoperator/Posh-SecMod.git
</pre>

The module should now be available and you can load the module and look at the functions it provides:
<pre>
Import-Module posh-secmod
Get-Command -Module posh-secmod
</pre>
