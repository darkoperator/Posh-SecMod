#
# Module manifest for module 'Posh-SecMod'
#
# Generated by: Carlos Perez
#
# Generated on: 6/29/2012
#

@{

# Script module or binary module file associated with this manifest
ModuleToProcess = 'Posh-SecMod.psm1'

# Version number of this module.
ModuleVersion = '1.3'

# ID used to uniquely identify this module
GUID = '01aa873e-e21a-4f2f-a103-24904b2bfd5b'

# Author of this module
Author = 'Carlos Perez'

# Company or vendor of this module
CompanyName = 'Unknown'

# Copyright statement for this module
Copyright = '(c) 2013 Carlos Perez. All rights reserved.'

# Description of the functionality provided by this module
Description = ''

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Name of the Windows PowerShell host required by this module
PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
PowerShellHostVersion = ''

# Minimum version of the .NET Framework required by this module
DotNetFrameworkVersion = '4.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '4.0'

# Processor architecture (None, X86, Amd64, IA64) required by this module
ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @("Assemblies\ARSoft.Tools.Net.dll","Assemblies\IPhelper.dll", "Assemblies\JHSoftware.DnsClient.dll", 
"Assemblies\WebTools.dll","Assemblies\filetimestamp.dll")

# Script files (.ps1) that are run in the caller's environment prior to importing this module
ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @()

# Modules to import as nested modules of the module specified in ModuleToProcess
NestedModules = "Discovery\Discovery.psm1",'Parse\Parse.psm1','Registry\Registry.psm1',
'PostExploitation\PostExploitation.psm1',"utility\utility.psm1","Database\Database.psm1", "Audit\Audit.psm1"

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

# List of all modules packaged with this module
ModuleList = @("Discovery",'PostExploitation','Registry','Database','Utility')

# List of all files packaged with this module
FileList = @()

# Private data to pass to the module specified in ModuleToProcess
PrivateData = ''

}

