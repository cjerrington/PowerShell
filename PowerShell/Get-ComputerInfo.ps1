# Computer information
# Functions include
#   Get-SystemUptime
#   Get-WifiPasswords
#   Get-WindowsProductKey
#   Get-MSOfficeKeys
#   Get-ComputerInfo
#   Get-IPMAC
#   Get-InstalledSoftware
#   Get-PendingReboot
#   Various Domain Health Items

#get system up time
function Get-SystemUptime{
    $operatingSystem = Get-WmiObject Win32_OperatingSystem
    [Management.ManagementDateTimeConverter]::ToDateTime($operatingSystem.LastBootUpTime)
}

# Get available wifi passwords
function Get-WifiPasswords{
  (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches | % {$_.Groups[1].Value.Trim()}; $_} |%{(netsh wlan show profile name="$name" key=clear)} | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches | % {$_.Groups[1].Value.Trim()}; $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize
}

#Get windows product key
function Get-WindowsProductKey{
	[CmdletBinding()]
	param(
		[Parameter(
			Position=0,
			HelpMessage='ComputerName or IPv4-Address of the remote computer')]
		[String[]]$ComputerName = $env:COMPUTERNAME,

		[Parameter(
			Position=1,
			HelpMessage='Credentials to authenticate agains a remote computer')]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.CredentialAttribute()]
		$Credential
	)

	Begin{
		$LocalAddress = @("127.0.0.1","localhost",".","$($env:COMPUTERNAME)")

		[System.Management.Automation.ScriptBlock]$Scriptblock = {
			$ProductKeyValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").digitalproductid[0x34..0x42]
			$Wmi_Win32OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property Caption, CSDVersion, Version, OSArchitecture, BuildNumber, SerialNumber

			[pscustomobject] @{
				ProductKeyValue = $ProductKeyValue
				Wmi_Win32OperatingSystem = $Wmi_Win32OperatingSystem
			}
		}
	}

	Process{
		foreach($ComputerName2 in $ComputerName)
		{
			$Chars="BCDFGHJKMPQRTVWXY2346789"

			# Don't use Invoke-Command on local machine. Prevent errors if WinRM is not configured
			if($LocalAddress -contains $ComputerName2)
			{
				$ComputerName2 = $env:COMPUTERNAME

				$Scriptblock_Result = Invoke-Command -ScriptBlock $Scriptblock
			}
			else
			{
				if(-not(Test-Connection -ComputerName $ComputerName2 -Count 2 -Quiet))
				{
					Write-Error -Message "$ComputerName2 is not reachable via ICMP!" -Category ConnectionError
					continue
				}

				try {
					if($PSBoundParameters['Credential'] -is [System.Management.Automation.PSCredential])
					{
						$Scriptblock_Result = Invoke-Command -ScriptBlock $Scriptblock -ComputerName $ComputerName2 -Credential $Credential -ErrorAction Stop
					}
					else
					{
						$Scriptblock_Result = Invoke-Command -ScriptBlock $Scriptblock -ComputerName $ComputerName2 -ErrorAction Stop
					}
				}
				catch {
					Write-Error -Message "$($_.Exception.Message)" -Category ConnectionError
					continue
				}
			}

			$ProductKey = ""

			for($i = 24; $i -ge 0; $i--)
			{
				$r = 0

				for($j = 14; $j -ge 0; $j--)
				{
					$r = ($r * 256) -bxor $Scriptblock_Result.ProductKeyValue[$j]
					$Scriptblock_Result.ProductKeyValue[$j] = [math]::Floor([double]($r/24))
					$r = $r % 24
				}

				$ProductKey = $Chars[$r] + $ProductKey

				if (($i % 5) -eq 0 -and $i -ne 0)
				{
					$ProductKey = "-" + $ProductKey
				}
			}

			[pscustomobject] @{
				#ComputerName = $ComputerName2
				#Caption = $Scriptblock_Result.Wmi_Win32OperatingSystem.Caption
				#CSDVersion = $Scriptblock_Result.Wmi_Win32OperatingSystem.CSDVersion
				#WindowsVersion = $Scriptblock_Result.Wmi_Win32OperatingSystem.Version
				#OSArchitecture = $Scriptblock_Result.Wmi_Win32OperatingSystem.OSArchitecture
				#BuildNumber = $Scriptblock_Result.Wmi_Win32OperatingSystem.BuildNumber
				#SerialNumber = $Scriptblock_Result.Wmi_Win32OperatingSystem.SerialNumber
				ProductKey = $ProductKey
			}
		}
	}

	End{

	}
}

# Get MS Office keys
function Search-RegistryKeyValues {
 param(
 [string]$path,
 [string]$valueName
 )
 Get-ChildItem $path -recurse -ea SilentlyContinue |
 % {
  if ((Get-ItemProperty -Path $_.PsPath -ea SilentlyContinue) -match $valueName)
  {
   $_.PsPath
  }
 }
}

function Get-MSOfficeKeys{
    # find registry key that has value "digitalproductid"
    # 32-bit versions
    $key = Search-RegistryKeyValues "hklm:\software\microsoft\office" "digitalproductid"
    if ($key -eq $null) {
        # 64-bit versions
     $key = Search-RegistryKeyValues "hklm:\software\Wow6432Node\microsoft\office" "digitalproductid"
     if ($key -eq $null) {Write-Host "MS Office is not installed.";break}
    }

    $valueData = (Get-ItemProperty $key).digitalproductid[52..66]

    # decrypt base24 encoded binary data
    $productKey = ""
    $chars = "BCDFGHJKMPQRTVWXY2346789"
    for ($i = 24; $i -ge 0; $i--) {
     $r = 0
     for ($j = 14; $j -ge 0; $j--) {
      $r = ($r * 256) -bxor $valueData[$j]
      $valueData[$j] = [math]::Truncate($r / 24)
      $r = $r % 24
     }
     $productKey = $chars[$r] + $productKey
     if (($i % 5) -eq 0 -and $i -ne 0) {
      $productKey = "-" + $productKey
     }
    }
    Write-Host "MS Office Product Key:" $productKey
}

# Base Computer Info
function Get-ComputerInfo{

<#
.SYNOPSIS
   This function query some basic Operating System and Hardware Information from
   a local or remote machine.

.DESCRIPTION
   This function query some basic Operating System and Hardware Information from
   a local or remote machine.
   It requires PowerShell version 3 for the Ordered Hashtable.

   The properties returned are the Computer Name (ComputerName),the Operating
   System Name (OSName), Operating System Version (OSVersion), Memory Installed
   on the Computer in GigaBytes (MemoryGB), the Number of
   Processor(s) (NumberOfProcessors), Number of Socket(s) (NumberOfSockets),
   and Number of Core(s) (NumberOfCores).

   This function as been tested against Windows Server 2000, 2003, 2008 and 2012

.PARAMETER ComputerName
   Specify a ComputerName or IP Address. Default is Localhost.

.PARAMETER ErrorLog
   Specify the full path of the Error log file. Default is .\Errors.log.

.PARAMETER Credential
   Specify the alternative credential to use

.EXAMPLE
   Get-ComputerInfo

   ComputerName       : XAVIER
   OSName             : Microsoft Windows 8 Pro
   OSVersion          : 6.2.9200
   MemoryGB           : 4
   NumberOfProcessors : 1
   NumberOfSockets    : 1
   NumberOfCores      : 4

   This example return information about the localhost. By Default, if you don't
   specify a ComputerName, the function will run against the localhost.

.EXAMPLE
   Get-ComputerInfo -ComputerName SERVER01

   ComputerName       : SERVER01
   OSName             : Microsoft Windows Server 2012
   OSVersion          : 6.2.9200
   MemoryGB           : 4
   NumberOfProcessors : 1
   NumberOfSockets    : 1
   NumberOfCores      : 4

   This example return information about the remote computer SERVER01.

.EXAMPLE
   Get-Content c:\ServersList.txt | Get-ComputerInfo

   ComputerName       : DC
   OSName             : Microsoft Windows Server 2012
   OSVersion          : 6.2.9200
   MemoryGB           : 8
   NumberOfProcessors : 1
   NumberOfSockets    : 1
   NumberOfCores      : 4

   ComputerName       : FILESERVER
   OSName             : Microsoft Windows Server 2008 R2 Standard
   OSVersion          : 6.1.7601
   MemoryGB           : 2
   NumberOfProcessors : 1
   NumberOfSockets    : 1
   NumberOfCores      : 1

   ComputerName       : SHAREPOINT
   OSName             : Microsoft(R) Windows(R) Server 2003 Standard x64 Edition
   OSVersion          : 5.2.3790
   MemoryGB           : 8
   NumberOfProcessors : 8
   NumberOfSockets    : 8
   NumberOfCores      : 8

   ComputerName       : FTP
   OSName             : Microsoft Windows 2000 Server
   OSVersion          : 5.0.2195
   MemoryGB           : 4
   NumberOfProcessors : 2
   NumberOfSockets    : 2
   NumberOfCores      : 2

   This example show how to use the function Get-ComputerInfo in a Pipeline.
   Get-Content Cmdlet Gather the content of the ServersList.txt and send the
   output to Get-ComputerInfo via the Pipeline.

.EXAMPLE
   Get-ComputerInfo -ComputerName FILESERVER,SHAREPOINT -ErrorLog d:\MyErrors.log.

   ComputerName       : FILESERVER
   OSName             : Microsoft Windows Server 2008 R2 Standard
   OSVersion          : 6.1.7601
   MemoryGB           : 2
   NumberOfProcessors : 1
   NumberOfSockets    : 1
   NumberOfCores      : 1

   ComputerName       : SHAREPOINT
   OSName             : Microsoft(R) Windows(R) Server 2003 Standard x64 Edition
   OSVersion          : 5.2.3790
   MemoryGB           : 8
   NumberOfProcessors : 8
   NumberOfSockets    : 8
   NumberOfCores      : 8

   This example show how to use the function Get-ComputerInfo against multiple
   Computers. Using the ErrorLog Parameter, we send the potential errors in the
   file d:\Myerrors.log.

.INPUTS
   System.String

.OUTPUTS
   System.Management.Automation.PSCustomObject

.NOTES
   Scripting Games 2013 - Advanced Event #2
#>

 [CmdletBinding()]

    PARAM(
    [Parameter(ValueFromPipeline=$true)]
    [String[]]$ComputerName = "LocalHost",

    [String]$ErrorLog = ".\Errors.log",

    [Alias("RunAs")]
    [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
    )#PARAM

    BEGIN {}#PROCESS BEGIN

    PROCESS{
        FOREACH ($Computer in $ComputerName) {
            Write-Verbose -Message "PROCESS - Querying $Computer ..."

            TRY{
                $Splatting = @{
                    ComputerName = $Computer
                }

                IF ($PSBoundParameters["Credential"]){
                    $Splatting.Credential = $Credential
                }


                $Everything_is_OK = $true
                Write-Verbose -Message "PROCESS - $Computer - Testing Connection"
                Test-Connection -Count 1 -ComputerName $Computer -ErrorAction Stop -ErrorVariable ProcessError | Out-Null

                # Query WMI class Win32_OperatingSystem
                Write-Verbose -Message "PROCESS - $Computer - WMI:Win32_OperatingSystem"
                $OperatingSystem = Get-WmiObject -Class Win32_OperatingSystem @Splatting -ErrorAction Stop -ErrorVariable ProcessError

                # Query WMI class Win32_ComputerSystem
                Write-Verbose -Message "PROCESS - $Computer - WMI:Win32_ComputerSystem"
                $ComputerSystem = Get-WmiObject -Class win32_ComputerSystem @Splatting -ErrorAction Stop -ErrorVariable ProcessError

                # Query WMI class Win32_Processor
                Write-Verbose -Message "PROCESS - $Computer - WMI:Win32_Processor"
                $Processors = Get-WmiObject -Class win32_Processor @Splatting -ErrorAction Stop -ErrorVariable ProcessError

                # Processors - Determine the number of Socket(s) and core(s)
                # The following code is required for some old Operating System where the
                # property NumberOfCores does not exist.
                Write-Verbose -Message "PROCESS - $Computer - Determine the number of Socket(s)/Core(s)"
                $Cores = 0
                $Sockets = 0
                FOREACH ($Proc in $Processors){
                    IF($Proc.numberofcores -eq $null){
                        IF ($Proc.SocketDesignation -ne $null){$Sockets++}
                        $Cores++
                    }ELSE {
                        $Sockets++
                        $Cores += $proc.numberofcores
                    }#ELSE
                }#FOREACH $Proc in $Processors

            }CATCH{
                $Everything_is_OK = $false
                Write-Warning -Message "Error on $Computer"
                $Computer | Out-file -FilePath $ErrorLog -Append -ErrorAction Continue
                $ProcessError | Out-file -FilePath $ErrorLog -Append -ErrorAction Continue
                Write-Warning -Message "Logged in $ErrorLog"

            }#CATCH


            IF ($Everything_is_OK){
                Write-Verbose -Message "PROCESS - $Computer - Building the Output Information"
                $Info = [ordered]@{
                    "ComputerName" = $OperatingSystem.__Server;
                    "OSName" = $OperatingSystem.Caption;
                    "OSVersion" = $OperatingSystem.version;
                    "MemoryGB" = $ComputerSystem.TotalPhysicalMemory/1GB -as [int];
                    "NumberOfProcessors" = $ComputerSystem.NumberOfProcessors;
                    "NumberOfSockets" = $Sockets;
                    "NumberOfCores" = $Cores}

                $output = New-Object -TypeName PSObject -Property $Info
                $output
            } #end IF Everything_is_OK
        }#end Foreach $Computer in $ComputerName
    }#PROCESS BLOCK
    END{
        # Cleanup
        Write-Verbose -Message "END - Cleanup Variables"
        Remove-Variable -Name output,info,ProcessError,Sockets,Cores,OperatingSystem,ComputerSystem,Processors,
        ComputerName, ComputerName, Computer, Everything_is_OK -ErrorAction SilentlyContinue

        # End
        Write-Verbose -Message "END - Script End !"
    }#END BLOCK
}#function

#Get IP and MAC of computer
function Get-IPMAC {
  <#
        .Synopsis
        Function to retrieve IP & MAC Address of a Machine.
        .DESCRIPTION
        This Function will retrieve IP & MAC Address of local and remote machines.
        .EXAMPLE
        PS>Get-ipmac -ComputerName viveklap
        Getting IP And Mac details:
        --------------------------

        Machine Name : TESTPC
        IP Address : 192.168.1.103
        MAC Address: 48:D2:24:9F:8F:92
        .INPUTS
        System.String[]
        .NOTES
        Author - Vivek RR
        Adapted logic from the below blog post
        "http://blogs.technet.com/b/heyscriptingguy/archive/2009/02/26/how-do-i-query-and-retrieve-dns-information.aspx"
#>

Param
(
    #Specify the Device names
    [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            Position=0)]
    [string[]]$ComputerName
)
    Write-Host "Getting IP And Mac details:`n---------------------------------`n" -for yellow
    foreach ($Inputmachine in $ComputerName )
    {
        if (!(test-Connection -Cn $Inputmachine -quiet))
            {
            Write-Host "$Inputmachine : Is offline`n" -BackgroundColor Red
            }
        else
            {

            $MACAddress = "N/A"
            $IPAddress = "N/A"
            $IPAddress = ([System.Net.Dns]::GetHostByName($Inputmachine).AddressList[0]).IpAddressToString
            #$IPMAC | select MACAddress
            $IPMAC = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $Inputmachine
            $MACAddress = ($IPMAC | where { $_.IpAddress -eq $IPAddress}).MACAddress
            Write-Host "Machine Name : $Inputmachine`nIP Address : $IPAddress`nMAC Address: $MACAddress`n"

            }
    }
}

# Get Installed Software
function Get-InstalledSoftware
	{
	[CmdletBinding()]
	param(
		[Parameter(
			Position=0,
			HelpMessage='Search for product name (You can use wildcards like "*ProductName*')]
		[String]$Search,

		[Parameter(
			Position=1,
			HelpMessage='ComputerName or IPv4-Address of the remote computer')]
		[String]$ComputerName = $env:COMPUTERNAME,

		[Parameter(
			Position=2,
			HelpMessage='Credentials to authenticate agains a remote computer')]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.CredentialAttribute()]
		$Credential
	)

	Begin{
		$LocalAddress = @("127.0.0.1","localhost",".","$($env:COMPUTERNAME)")

		[System.Management.Automation.ScriptBlock]$ScriptBlock = {
			# Location where all entrys for installed software should be stored
			return Get-ChildItem -Path  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Get-ItemProperty | Select-Object -Property DisplayName, Publisher, UninstallString, InstallLocation, InstallDate
		}
	}

	Process{
		if($LocalAddress -contains $ComputerName)
		{
			$Strings = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $Search
		}
		else
		{
			if(Test-Connection -ComputerName $ComputerName -Count 2 -Quiet)
			{
				try {
					if($PSBoundParameters.ContainsKey('Credential'))
					{
						$Strings = Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $ComputerName -ArgumentList $Search -Credential $Credential -ErrorAction Stop
					}
					else
					{
						$Strings = Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $ComputerName -ArgumentList $Search -ErrorAction Stop
					}
				}
				catch {
					throw
				}
			}
			else
			{
				throw """$ComputerName"" is not reachable via ICMP!"
			}
		}

		foreach($String in $Strings)
		{
			# Check for each entry if data exists
			if((-not([String]::IsNullOrEmpty($String.DisplayName))) -and (-not([String]::IsNullOrEmpty($String.UninstallString))))
			{
				# Search (only if parameter is used)
				if((-not($PSBoundParameters.ContainsKey('Search'))) -or (($PSBoundParameters.ContainsKey('Search') -and ($String.DisplayName -like $Search))))
				{
					[pscustomobject] @{
						DisplayName = $String.DisplayName
						Publisher = $String.Publisher
						UninstallString = $String.UninstallString
						InstallLocation = $String.InstallLocation
						InstallDate = $String.InstallDate
					}
				}
			}
		}
	}

	End{

	}
}

# Get Pending Reboot
Function Get-PendingReboot{
<#
.SYNOPSIS
    Gets the pending reboot status on a local or remote computer.

.DESCRIPTION
    This function will query the registry on a local or remote computer and determine if the
    system is pending a reboot, from either Microsoft Patching or a Software Installation.
    For Windows 2008+ the function will query the CBS registry key as another factor in determining
    pending reboot state.  "PendingFileRenameOperations" and "Auto Update\RebootRequired" are observed
    as being consistant across Windows Server 2003 & 2008.

    CBServicing = Component Based Servicing (Windows 2008)
    WindowsUpdate = Windows Update / Auto Update (Windows 2003 / 2008)
    CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
    PendFileRename = PendingFileRenameOperations (Windows 2003 / 2008)

.PARAMETER ComputerName
    A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

.PARAMETER ErrorLog
    A single path to send error data to a log file.

.EXAMPLE
    PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize

    Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
    -------- ----------- ------------- ------------ -------------- -------------- -------------
    DC01     False   False           False      False
    DC02     False   False           False      False
    FS01     False   False           False      False

    This example will capture the contents of C:\ServerList.txt and query the pending reboot
    information from the systems contained in the file and display the output in a table. The
    null values are by design, since these systems do not have the SCCM 2012 client installed,
    nor was the PendingFileRenameOperations value populated.

.EXAMPLE
    PS C:\> Get-PendingReboot

    Computer     : WKS01
    CBServicing  : False
    WindowsUpdate      : True
    CCMClient    : False
    PendComputerRename : False
    PendFileRename     : False
    PendFileRenVal     :
    RebootPending      : True

    This example will query the local machine for pending reboot information.

.EXAMPLE
    PS C:\> $Servers = Get-Content C:\Servers.txt
    PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation

    This example will create a report that contains pending reboot information.

.LINK
    Component-Based Servicing:
    http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx

    PendingFileRename/Auto Update:
    http://support.microsoft.com/kb/2723674
    http://technet.microsoft.com/en-us/library/cc960241.aspx
    http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

    SCCM 2012/CCM_ClientSDK:
    http://msdn.microsoft.com/en-us/library/jj902723.aspx

.NOTES
    Author:  Brian Wilhite
    Email:   bcwilhite (at) live.com
    Date:    29AUG2012
    PSVer:   2.0/3.0/4.0/5.0
    Updated: 01DEC2014
    UpdNote: Added CCMClient property - Used with SCCM 2012 Clients only
       Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
       Removed $Data variable from the PSObject - it is not needed
       Bug with the way CCMClientSDK returned null value if it was false
       Removed unneeded variables
       Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
       Removed .Net Registry connection, replaced with WMI StdRegProv
       Added ComputerPendingRename
#>

	[CmdletBinding()]
	param (
		[Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias("CN", "Computer")]
		[String[]]$ComputerName = "$env:COMPUTERNAME",

		[String]$ErrorLog
	)

	Begin { } ## End Begin Script Block
	Process
	{
		Foreach ($Computer in $ComputerName)
		{
			Try
			{
				## Setting pending values to false to cut down on the number of else statements
				$CompPendRen, $PendFileRename, $Pending, $SCCM = $false, $false, $false, $false

				## Setting CBSRebootPend to null since not all versions of Windows has this value
				$CBSRebootPend = $null

				## Querying WMI for build version
				$WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop

				## Making registry connection to the local/remote computer
				$HKLM = [UInt32] "0x80000002"
				$WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"

				## If Vista/2008 & Above query the CBS Reg Key
				If ([Int32]$WMI_OS.BuildNumber -ge 6001)
				{
					$RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
					$CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"
				}

				## Query WUAU from the registry
				$RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
				$WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"

				## Query PendingFileRenameOperations from the registry
				$RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\Session Manager\", "PendingFileRenameOperations")
				$RegValuePFRO = $RegSubKeySM.sValue

				## Query ComputerName and ActiveComputerName from the registry
				$ActCompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\", "ComputerName")
				$CompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\", "ComputerName")
				If ($ActCompNm -ne $CompNm)
				{
					$CompPendRen = $true
				}

				## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
				If ($RegValuePFRO)
				{
					$PendFileRename = $true
				}

				## Determine SCCM 2012 Client Reboot Pending Status
				## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
				$CCMClientSDK = $null
				$CCMSplat = @{
					NameSpace = 'ROOT\ccm\ClientSDK'
					Class ='CCM_ClientUtilities'
					Name = 'DetermineIfRebootPending'
					ComputerName = $Computer
					ErrorAction = 'Stop'
				}
				## Try CCMClientSDK
				Try
				{
					$CCMClientSDK = Invoke-WmiMethod @CCMSplat
				}
				Catch [System.UnauthorizedAccessException] {
					$CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
					If ($CcmStatus.Status -ne 'Running')
					{
						Write-Warning "$Computer`: Error - CcmExec service is not running."
						$CCMClientSDK = $null
					}
				}
				Catch
				{
					$CCMClientSDK = $null
				}

				If ($CCMClientSDK)
				{
					If ($CCMClientSDK.ReturnValue -ne 0)
					{
						Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"
					}
					If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending)
					{
						$SCCM = $true
					}
				}

				Else
				{
					$SCCM = $null
				}

				## Creating Custom PSObject and Select-Object Splat
				$SelectSplat = @{
					Property = (
					'Computer',
					'CBServicing',
					'WindowsUpdate',
					'CCMClientSDK',
					'PendComputerRename',
					'PendFileRename',
					'PendFileRenVal',
					'RebootPending'
					)
				}
				New-Object -TypeName PSObject -Property @{
					Computer = $WMI_OS.CSName
					CBServicing = $CBSRebootPend
					WindowsUpdate = $WUAURebootReq
					CCMClientSDK = $SCCM
					PendComputerRename = $CompPendRen
					PendFileRename = $PendFileRename
					PendFileRenVal = $RegValuePFRO
					RebootPending = ($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
				} | Select-Object @SelectSplat

			}
			Catch
			{
				Write-Warning "$Computer`: $_"
				## If $ErrorLog, log the file to a user specified location/path
				If ($ErrorLog)
				{
					Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
				}
			}
		} ## End Foreach ($Computer in $ComputerName)
	} ## End Process

	End { } ## End End

} ## End Function Get-PendingReboot

# Get system manufacturer, model and serial
$computerManufacturer = (Get-WmiObject -Class:Win32_ComputerSystem).Manufacturer
$computerModel = (Get-WmiObject -Class:Win32_ComputerSystem).Model
$computerSerial=Get-WMIObject -Class Win32_Bios -computername $env:computername | select -expand serialnumber
$currentSSID = netsh wlan show interfaces | Select-String '\sSSID'
$currentSSID = ($currentSSID -split ":")[-1].Trim() -replace '"'

Write-Host "Basic Computer Info:"`n---------------------------------------------`n -for Yellow
Get-ComputerInfo -ComputerName $env:computername
Write-Host "Manufacturer: $computerManufacturer"
Write-Host "Model: $computerModel"
Write-Host "Serial: $computerSerial"
Write-Host ""
Write-Host "Your system has been running since:"`n---------------------------------------------`n -for Yellow
Get-SystemUptime
Write-Host "Your Windows Operating System product key is:"`n---------------------------------------------`n -for Yellow
Get-WindowsProductKey
Write-Host "Your Microsoft Office keys are:"`n---------------------------------------------`n -for Yellow
Get-MSOfficeKeys
#title is in the function
Write-Host ""
Get-IPMAC -ComputerName $env:computername
Write-Host "Installed Software:"`n---------------------------------------------`n -for Yellow
Get-InstalledSoftware
Write-Host "Gathering Pending Reboot:"`n---------------------------------------------`n -for Yellow
Get-PendingReboot
Write-Host "Gathering wifi data:"`n---------------------------------------------`n -for Yellow
Write-Host "Current SSID: $currentSSID"
Get-WifiPasswords
Write-Host "Getting Domain Health Stats:"`n---------------------------------------------`n -for Yellow
try{
    Get-ADDomainController
    Write-Host "DCDIAG"`n---------------------------------------------`n -for Yellow
    dcdiag /a
    Write-Host ""
    Write-Host ""
    # The replsummary operation quickly summarizes the replication state and relative health
    Write-Host "Replsummary"`n---------------------------------------------`n -for Yellow
    repadmin /replsummary
    Write-Host ""
    Write-Host ""
    # Displays the replication partners for each directory partition on the specified domain controller
    Write-Host "Showrepl"`n---------------------------------------------`n -for Yellow
    repadmin /showrepl
    Write-Host ""
    Write-Host ""
    # Query FSMO roles
    Write-Host "NETDOM Query FSMO"`n---------------------------------------------`n -for Yellow
    netdom query fsmo
    # Query Global Catalogs
    Write-Host "List Global Catalogs"`n---------------------------------------------`n -for Yellow
    nslookup -querytype=srv _gc._tcp.$env:USERDNSDOMAIN
 }Catch{
    Write-Host "No domain controller found"
 }
