<#PSScriptInfo

.VERSION 3.7.2

.GUID 78fe3fa8-add6-47e8-8c0c-06baf75ea954

.AUTHOR Mosaicmk Software

.COMPANYNAME Mosaicmk Software

.COPYRIGHT (c) 2021 MosaicMK Software. All rights reserved.

.TAGS Windows

.LICENSEURI https://opensource.org/licenses/MS-PL

.PROJECTURI https://www.mosaicmk.com//windows10setupscript

.ICONURI https://3.bp.blogspot.com/-5AH8bMtdvcU/XBpsEqKMoFI/AAAAAAAABIw/cRbUnQwTwdIpZapoCD4ifYatBmy717zSgCLcBGAs/s1600/logo-transparent_NoWords.png.ico

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES

#>

<#
.SYNOPSIS
Configures popular settings on a windows 10 workstation for first time use
.DESCRIPTION
This script can be used to remove built in windows 10 apps,Export a Custome Start Menu config file,Import a default start menu config file,
Disable OneDrive, Disbale Cortana, Disable Hibernate, Join a workstation to a domain, Rename the workstation, Set the page file size, Disable Windows Tips,
Disable the Consumer experience and Disable the Xbox Services.
.PARAMETER RemoveApps
Use this switch enable app removal
.PARAMETER AppsToRemove
Specifyes the list of apps to be removed, if not used then will use a list of apps built into the script
.PARAMETER StartMenuLayout
Specifyes the xml file for the start menu layout, Only new users on the device will get the layout
Accounts that already exist will not see a change. This is due to the fact that the layout is applied
to the default user profile.
.PARAMETER ExportStartMenuLayout
Exports the curent start menu layout to be used on other workstations
.PARAMETER DisableAds
Disables all ads and sujested apps from the start menu, explorer, and lock screen
.PARAMETER DisableOneDrive
Disables OneDrive on the workstation
.PARAMETER DisableCortana
Disables Cortana on the workstation
.PARAMETER DisableHibernate
Disables the hibernate power setting
.PARAMETER SetPowerConfig
Imports and sets a Power Config from a file
https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options
.PARAMETER DisableWindowsStore
Disables access to the Windows Store, The app is still listed
.PARAMETER RemoveWindowsStoreApp
Removes the windows store app
.PARAMETER DisableConsumerExperience
Disables The installation of extra apps and the pinning of links to Windows Store pages of third-party applications
by using this featurs like the phone app will no longer work
.PARAMETER JoinDomain
Joins the computer to a domain
.PARAMETER Account
Account used to join to a domain, if not specified you will be asked for the account
.PARAMETER Domain
Domain to join when the JoinDomain Parameter is used, if not specified you will be asked for the domain
.PARAMETER RenameComputer
Renames the workstation to what is specified for the parameter
.PARAMETER SetPageFile
Sets the page file size to the recomended size based on the ammount of memmory installed on the device
.PARAMETER PageFileDrive
Moves the page file to a new drive, if not specified will default to the C drive
When specifying a drive letter just use the letter for example -PageFileDrive D
.PARAMETER LogFile
Specifies the location of the logfile byt default it is set to C:\Win10Setup.log
the log file is in a foramt for cmtrace https://docs.microsoft.com/en-us/sccm/core/support/cmtrace
.PARAMETER DisableConnectToInternetUpdates
Unless specified with GPO or this reg key Windows 10 will look to other update locations to pull
critial updates that have not bet installed on the device
https://social.technet.microsoft.com/Forums/en-US/46f992d3-e4eb-466f-8993-b791193dae2d/forcing-windows-10-clients-to-pull-updates-from-wsus-only?forum=win10itprosetup
.PARAMETER Reboot
Reboots the computer after all other taskes have been performed
.PARAMETER SetTimeZone
Sets the Time Zone of the computer
.PARAMETER InstallDotNet35
Installs .Net 3.5 from source files
Source files can be located on the OS install media under D:\Sources\sxs directory
.PARAMETER DisableSMBv1
Disables SMBv1, May have issues conenction to SMB shares hosted on server 2008 R2 or older but
Effectively mitigates EternalBlue, popularly known as WannaCry.
.PARAMETER DisableLocationAndDataCollection
Disables Services that are used to share your location and collect data on
how the device is being used
.PARAMETER DisableXboxServices
Disbales the Xbox services and removes the apps from windows
.EXAMPLE
.\Win10Setup.ps1 -RemoveApps -AppsToRemove AppsList.txt
Removes all apps in the AppsList.txt file
.EXAMPLE
.\Win10Setup.ps1 -StartMenuLayout C:\example\StartMenuLayout.xml
Imports the xml file to use as the default start menu layout for all new users
To build your xml run Export-StartLayout -Path "C:\example\StartMenuLayout.xml"
.EXAMPLE
.\Win10Setup.ps1 -StartMenuLayout C:\example\StartMenuLayout.xml -RemoveApps -AppsToRemove C:\example\AppsToRemove.txt -DisableOneDrive -DisableCortana
Imports the start menu config, removes apps listed in the txt file. disbales OneDrive and cortana.
.EXAMPLE
.\Win10Setup.ps1 -StartMenuLayout C:\example\StartMenuLayout.xml -RemoveApps -InstallDotNet35 D:\sources\sxs -SetPowerConfig C:\example\PowerPlan.pow
Imports the start menu config, removes apps listed in the default list, Installs .Net 3.5 from the source files and sets the power config to the one stored in the config file
.NOTES
Contact: Contact@mosaicmk.com
Facebook: MosaicMK Software LLC
Version 3.7.2
.LINK
https://www.mosaicmk.com//windows10setupscript
#>

Param(
    [Switch]$RemoveApps,
    [string]$AppsToRemove,
    [string]$StartMenuLayout,
    [Switch]$SetPageFile,
    [String]$PageFileDrive,
    [Switch]$EnableRDP,
    [Switch]$DisableOneDrive,
    [Switch]$DisableCortana,
    [Switch]$DisableWindowsTips,
    [Switch]$DisableConsumerExperience,
    [Switch]$DisableHibernate,
    [String]$SetPowerConfig,
    [Switch]$DisableXboxServices,
    [Switch]$DisableAds,
    [Switch]$DisableWindowsStore,
    [Switch]$RemoveWindowsStoreApp,
    [Switch]$DisableConnectToInternetUpdates,
    [switch]$DisableUAC,
    [switch]$DisableLocationAndDataCollectionServices,
    [switch]$DisableSMBv1,
    [switch]$Harden,
    [string]$SetTimeZone,
    [string]$RenameComputer,
    [string]$InstallDotNet35,
    [String]$ExportStartMenuLayout,
    [Switch]$JoinDomain,
    [string]$Account,
    [string]$Domain,
    [Switch]$Reboot,
    [string]$LogFile = "C:\Win10Setup.log"
)

$ScriptName = $MyInvocation.MyCommand.Name
$OldProgressPreference = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'

function Invoke-Proccess {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Proccess,
        [string]$Arguments,
        [switch]$GetOutput
    )
    $Guid = (New-Guid).Guid
    $ErrorFile = "$env:TEMP\" + $GUID + '.error'
    $OutFile = "$env:TEMP\" + $GUID + '.out'
    Start-Process -filepath $Proccess -ArgumentList "$Arguments" -NoNewWindow -RedirectStandardError $ErrorFile -RedirectStandardOutput $OutFile -Wait
    $ErrorText = Get-Content $ErrorFile -Raw
    $OutText = Get-Content $OutFile -Raw
    Remove-Item $ErrorFile -Force | Out-Null
    Remove-Item $OutFile -Force | Out-null
    IF ($ErrorText){Throw $ErrorText}
    IF ($GetOutput){
        $OutPut = New-Object -TypeName psobject
        $OutPut | Add-Member -MemberType NoteProperty -Name Output -Value $OutText
        $OutPut
    }
}

function Read-Error{
    PARAM(
        [string]$ErrorText
    )
    Add-LogEntry -LogMessage $ErrorText -Messagetype 3
    Exit-Script
    exit 1
}

function New-LogFile{
    $LogFilePaths =  "$LogFile"
    Foreach ($LogFilePath in $LogFilePaths){
        $script:NewLogError = $null
        $script:ConfigMgrLogFile = $LogFilePath
        Add-LogEntry "********************************************************************************************************************" "1"
        Add-LogEntry "Log file successfully intialized for $ScriptName." 1
        If (-Not($script:NewLogError)) { break }
    }
    If ($script:NewLogError){
        $script:Returncode = 1
        Exit $script:Returncode
    }
}

function Add-LogEntry{
    PARAM(
        $LogMessage,
        $Messagetype = 1
    )
    # Date and time is set to the CMTrace standard
    # The Number after the log message in each function corisponts to the message type
    # 1 is info
    # 2 is a warning
    # 3 is a error
    If ($Messagetype -eq 1){Write-Host "$LogMessage"}
    If ($Messagetype -eq 2){Write-Warning "$LogMessage"}
    If ($Messagetype -eq 3){Write-Error "$LogMessage"}
    Add-Content $script:ConfigMgrLogFile "<![LOG[$LogMessage]LOG]!><time=`"$((Get-Date -format HH:mm:ss)+".000+300")`" date=`"$(Get-Date -format MM-dd-yyyy)`" component=`"$ScriptName`" context=`"`" type=`"$Messagetype`" thread=`"`" file=`"powershell.exe`">"  -Errorvariable script:NewLogError
}

function Exit-Script{
    $ProgressPreference = $OldProgressPreference
    Add-LogEntry "Closing the log file for $ScriptName."
    Add-LogEntry "********************************************************************************************************************"
}

Function Export-StartMenuLayout{
    Export-StartLayout -Path "$ExportStartMenuLayout"
    Write-Host "Config Saved To: $ExportStartMenuLayout"
    exit 0
}

Function Import-StartMenuLayout{
    Add-LogEntry -LogMessage "Importing startmenu layout: $StartMenuLayout"
    try {
        $startMenuTemplate = "$PSScriptRoot\start2.bin"
        $defaultStartMenuPath = $env:USERPROFILE.Replace($env:USERNAME, 'Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState')
        if (-not(Test-Path $defaultStartMenuPath)) {
            new-item $defaultStartMenuPath -ItemType Directory -Force | Out-Null
            Write-Output "Created LocalState folder for default user profile"
        }
        Copy-Item -Path $startMenuTemplate -Destination $defaultStartMenuPath -Force

    }catch {Add-LogEntry -LogMessage "ERROR: Unable to import start menu layout: $_" -Messagetype 3}
}

Function Set-Reg{
PARAM(
    [String]$RegPath,
    [String]$Name,
    [String]$Value,
    [string]$Type
)
if (!(test-Path $RegPath -ErrorAction SilentlyContinue)) {New-Item $RegPath}
    try {New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop} catch {Throw $_}
}

Function Disable-OneDrive{
    Add-LogEntry -LogMessage "Disabling OneDrive"
    try {
        Set-Reg -RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value "1" -Type "DWORD"
        Add-LogEntry -LogMessage "SUCCESS:OneDrive scusessfuly disabled"
    } catch {Add-LogEntry "ERROR: Unale to disble OneDrive: $_" -Messagetype 3}
    taskkill /f /im OneDrive.exe
    Start-Process -FilePath "C:\Windows\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
}

Function Disable-XboxServices{
    Add-LogEntry  -LogMessage "Disabling Xbox Services"
    try {
        Get-Service XblAuthManager -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
        Get-Service XblGameSave -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
        Get-Service XboxNetApiSvc -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
        $AppsList = Get-AppxPackage -AllUsers | where-object {$_.displayname -like "*xbox*"}
        if ($AppsList){
            foreach($Item in $AppsList){
                $app = '*' + $item + '*'
                Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction Continue
                Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like $app } | ForEach-Object { Remove-ProvisionedAppxPackage -Online -AllUsers -PackageName $_.PackageName }
            }
        }
        Add-LogEntry -LogMessage "SUCCESS: Disabled Xbox Services"
    }catch {Add-LogEntry -LogMessage "ERROR: Unable to Disable Xbox Services: $_" -Messagetype 3}
}

Function Disable-UAC{
    Add-LogEntry -LogMessage "Disabling UAC"
    try {
        Set-Reg -RegPath "HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system" -Type Dword -Value 0 -Name EnableLUA
        Set-Reg -RegPath "HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system" -Type Dword -Value 00000000 -Name "ConsentPromptBehaviorAdmin"
        Add-LogEntry -LogMessage "SUCCESS: Disabled UAC"
    }
    catch {Add-LogEntry -LogMessage "ERROR: Unable to disable UAC: $_" -Messagetype 3}
}

Function Disable-Cortana{
    Add-LogEntry -LogMessage "Disabling Cortana"
    try {
        Set-Reg -Name "AllowCortana" -RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Value 0 -Type DWORD
        Add-LogEntry -LogMessage "SUCCESS: disabled Cortana"
    }
    catch {Add-LogEntry -LogMessage "ERROR: Unable to disable Cortana: $_" -Messagetype 3}
}

Function Disable-WindowsTips{
    try {
        Set-Reg -Name "DisableSoftLanding" -RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Value "1" -Type "DWORD"
        New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop
        Add-LogEntry -LogMessage "SUCCESS: disabled Windows Tips"
    }
    catch {Add-LogEntry -LogMessage "ERROR: Unsable to disable Windows Tips: $_" -Messagetype 3}
}

Function Disable-ConsumerExperience{
    Add-LogEntry -LogMessage 'Disabling Consumer Experience'
    try {
        Set-Reg -Name "DisableWindowsConsumerFeatures" -RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Value "1" -Type "DWORD"
        Add-LogEntry -LogMessage "SUCCESS: disabled Consumer Experience"
    }catch {Add-LogEntry -LogMessage "ERROR: Unable to disabled Consumer Experience: $_" -Messagetype 3}
}

Function Disable-Hibernate{
    Add-LogEntry -LogMessage "Disabling Hibernate"
    powercfg.exe /hibernate off
    If (!(test-Path -path $Env:SystemDrive\Hiberfil.sys)){
        Add-LogEntry -LogMessage "SUCCESS: Hibernate Disabled"
    }
    IF (Test-Path -Path $Env:SystemDrive\Hiberfil.sys){Add-LogEntry -LogMessage "ERROR: Hibernate was not disabled" -Messagetype 3}
}

Function Disable-Ads{
    $reglocation = "HKCU"
    #Start menu ads
    Add-LogEntry 'Disabling Start Menu Ads for Current User'
    Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SystemPaneSuggestionsEnabled" /D 0 /F
    #Lock Screen suggestions
    Add-LogEntry 'Disabling Lock Screen Suggentions for Current User'
    Reg Add "$reglocation\SOFTWARE\Microsoft\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SoftLandingEnabled" /D 0 /F
    Add-LogEntry "Disabling explorer ads for current user"
    Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /T REG_DWORD /V "ShowSyncProviderNotifications" /D 0 /F

    $reglocation = "HKLM\AllProfile"
    reg load "$reglocation" c:\users\default\ntuser.dat
    IF ($LASTEXITCODE -ne 0) {Add-LogEntry "Could not mount default user profile reg hive" -Messagetype 3}
    IF ($LASTEXITCODE -eq 0){
        Add-LogEntry 'Disabling Start Menu Ads for default user'
        Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SystemPaneSuggestionsEnabled" /D 0 /F
        IF ($LASTEXITCODE -ne 0) {Add-LogEntry "ERROR: Could not disable Start Menu Ads for default user" -Messagetype 3} Else {Add-LogEntry -LogMessage "SUCCESS: Disabled Start Menu Ads for default user"}

        Add-LogEntry 'Disabling Lock Screen Suggentions for Current User'
        Reg Add "$reglocation\SOFTWARE\Microsoft\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SoftLandingEnabled" /D 0 /F
        IF ($LASTEXITCODE -ne 0) {Add-LogEntry "ERROR: Could not disable Lock Screen Suggentions for Current User" -Messagetype 3}Else {Add-LogEntry -LogMessage "SUCCESS: Disabled Lock Screen Suggentions for Current User"}

        Add-LogEntry "Disabling explorer ads for default user"
        Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /T REG_DWORD /V "ShowSyncProviderNotifications" /D 0 /F
        IF ($LASTEXITCODE -ne 0) {Add-LogEntry "ERROR: Could not disable explorer ads for default user" -Messagetype 3}Else {Add-LogEntry -LogMessage "SUCCESS: Disabled explorer ads for default user"}
        #unload default user hive
        [gc]::collect()
        reg unload "$reglocation"
        IF ($LASTEXITCODE -ne 0) {Add-LogEntry "ERROR: Could not dismount default user reg hive" -Messagetype 3}
    }
}

Function Disable-WindowsStore{
    try {
        Set-Reg -Name "RemoveWindowsStore" -RegPath "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Value "1" -Type "DWORD"
        Set-Reg -Name "DisableSoftLanding" -RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Value "1" -Type "DWORD"
        Add-LogEntry -LogMessage "SUCCESS: Windows Store was disabled"
    }
    catch {Add-LogEntry -LogMessage "ERROR: Windows Store was not disabled: $_" -Messagetype 3}
}

Function Remove-WindowsStoreApp{
    $App = Get-AppxProvisionedPackage -online | where-object -Property displayname -like "Microsoft.WindowsStore"
    try {
        Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName -ErrorAction Stop | Out-Null
        Add-LogEntry -LogMessage "SUCCESS: $name Provisioned Package was succefully removed"
    } catch {
        Add-LogEntry -LogMessage "Could not remove $name Provisioned Package, will retry: $_" -Messagetype 2
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName -ErrorAction Stop | Out-Null
            Add-LogEntry "SUCCESS: Retry for removal of $name Provisioned Pakcage was succefull"
        } catch {Add-LogEntry -LogMessage "ERROR: Could not remove $Name Provisioned Package: $_" -Messagetype 3}
    }

    try {
        Get-AppxPackage -AllUsers -Name $App.DisplayName | Remove-AppxPackage -ErrorAction Stop | Out-Null
        Add-LogEntry -LogMessage "SUCCESS: $Name package was succefully removed"
    } catch {
        Add-LogEntry -LogMessage "$Name package was not removed, will retry: $_" -Messagetype 2
        try {
            Get-AppxPackage -AllUsers -Name $App.DisplayName | Remove-AppxPackage -ErrorAction Stop | Out-Null
            Add-LogEntry -LogMessage "SUCCESS: $Name package was succefully removed"
        } catch {Add-LogEntry -LogMessage "ERROR: $Name package was not removed: $_" -Messagetype 3}
    }
}

Function Remove-Apps{
    Add-LogEntry -LogMessage "Starting App Removeal" -Messagetype 1
    If ($AppsToRemove){
        If (!(Test-Path $AppsToRemove)){Read-Error -ErrorText "ERROR: Could not find $AppsToRemove"}
        $AppsList = Get-Content $AppsToRemove
    }

    If (!($AppsToRemove)){$AppsList = Get-Content "$PSScriptRoot\AppList.txt"}
        #Removes some windows apps
    Foreach ($item in $AppsList){
        $app = '*' + $item + '*'
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction Continue
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like $app } | ForEach-Object { Remove-ProvisionedAppxPackage -Online -AllUsers -PackageName $_.PackageName }
    }
}

Function Set-PageFile{
    #Gets total memory
    $Getmemorymeasure = Get-WMIObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    #Converts the memory into GB
    $TotalMemSize = $($Getmemorymeasure.sum/1024/1024/1024)

    if (!($PageFileDrive)){$Drive = "C:"}else{IF ($PageFileDrive -like "*:"){$Drive = $PageFileDrive}else{$Drive = $PageFileDrive + ":"}}
    #recomended Page file size is double the memory installed
    Add-LogEntry -LogMessage "Setting Page file size on: $Drive"
    Add-LogEntry -LogMessage "Total Memory Installed (gb): $TotalMemSize"
    try {
            #2gb
            If (($TotalMemSize -gt "1") -and ($TotalMemSize -le "2.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 4096 4096" -ErrorAction Stop}
            #4gb
            If (($TotalMemSize -gt "2") -and ($TotalMemSize -le "4.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 8194 8194" -ErrorAction Stop}
            #6gb
            If (($TotalMemSize -gt "4") -and ($TotalMemSize -le "6.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 12288 12288" -ErrorAction Stop}
            #8gb
            If (($TotalMemSize -gt "6") -and ($TotalMemSize -le "8.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 16384 16384" -ErrorAction Stop}
            #12
            If (($TotalMemSize -gt "8") -and ($TotalMemSize -le "12.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 24576 24576" -ErrorAction Stop}
            #16
            If (($TotalMemSize -gt "12") -and ($TotalMemSize -le "16.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 32768 32768" -ErrorAction Stop}
            #24
            If (($TotalMemSize -gt "16") -and ($TotalMemSize -le "24.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 49152 49152" -ErrorAction Stop}
            #32
            If (($TotalMemSize -gt "24") -and ($TotalMemSize -le "32.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 65536 65536" -ErrorAction Stop}
            #64
            If (($TotalMemSize -gt "32") -and ($TotalMemSize -le "64.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 131072 131072" -ErrorAction Stop}
            Add-LogEntry -LogMessage "SUCCESS: Set page file size"
        }catch {Add-LogEntry -LogMessage "ERROR: Could not set page file: $_" -Messagetype 3}
}

function Enable-RDP{
    Add-LogEntry -LogMessage "Enabling RDP"
    try {
        Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled "False" -ErrorAction Stop
        If (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections"){Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value "0"}Else{New-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value "0"}
        Add-LogEntry -LogMessage "SUCCESS: Enabled RDP"
    }catch {Add-LogEntry "ERROR: Could not enable RDP: $_" -Messagetype 3}
}

function Join-Domain{
    IF (!($Domain)) {$domain = Read-Host "Domain"}
    IF (!($Account)) {$account = Read-Host "Account"}
    $password = Read-Host "Password for $Account" -AsSecureString
    Write-host "Joining $Domain as $Account"
    $username = "$domain\$account"
    $credential = New-Object System.Management.Automation.PSCredential($username,$password)
    Add-Computer -DomainName $domain -Credential $credential
    $password = $null
    $credential = $null
}

Function Set-Time{
    Add-LogEntry -LogMessage "Setting Time Zone"
    try {
        Set-TimeZone -Name "$SetTimeZone" -ErrorAction Stop
        Add-LogEntry -LogMessage "SUCCESS: set Time Zone"
    } catch {Add-LogEntry -LogMessage "ERROR: Could not set Time Zone" -Messagetype 3}
}

Function Set-PowerConfig{
    Add-LogEntry -LogMessage "Setting power config"
    $out = Invoke-Proccess -Proccess powercfg.exe -Arguments "/IMPORT `"$SetPowerConfig`"" -GetOutput
    $guid = $out.Output.substring(42)
    Invoke-Proccess -Proccess powercfg.exe -Arguments "/s $guid"
}

Function Disable-ConnectToInternetUpdates{
    Add-LogEntry -LogMessage 'Disabling Connect To Internet Updates'
    try {
        Set-Reg -Name "DoNotConnectToWindowsUpdateInternetLocations" -RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Type "DWORD" -Value "1"
        Add-LogEntry -LogMessage 'SUCCESS: Connect to Internet for Updates was disabled'
    } catch {Add-LogEntry -LogMessage "ERROR: Connect to Internet for Updates was not disabled: $_" -Messagetype 3}
}

function Install-Dotnet {
    Add-LogEntry -LogMessage "Installing .Net 3.5"
    try {
        Get-WindowsCapability -Name "NetFx3*" -Online | Add-WindowsCapability -Online -Source $InstallDotNet35 -InformationAction SilentlyContinue -ErrorAction Stop | Out-Null
        Add-LogEntry -LogMessage "SUCCESS: .Net 3.5 was installed"
    }
    catch {Add-LogEntry -LogMessage "Unable to install .Net 3.5 : $_" -Messagetype 3}
}

Function Disable-SMBv1 {
    Add-LogEntry -LogMessage "Disabling SMBv1"
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force
        Get-Service mrxsmb10 -ErrorAction SilentlyContinue | stop-service -passthru -ErrorAction SilentlyContinue | set-service -startuptype disabled -ErrorAction SilentlyContinue
    }
    catch {Add-LogEntry -LogMessage "Unable to Disable SMBv1"}
}

function Disable-LocationAndDataCollection {
    #Disables Diag and feed back
    Get-Service diagtrack -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
    Get-Service diagnosticshub.standardcollector.service -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
    #Disables Location Services
    Get-Service lfsvc -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
    Get-Service MapsBroker -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
    # Remove Metadata Tracking
    Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Force -Recurse | Out-Null
    # Disabling Tracking Services and Data Collection
    Set-Reg -Name AllowTelemetry -RegPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Type "DWORD" -Value 0
    Set-Reg -Name AllowTelemetry -RegPath "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Type "DWORD" -Value 0
}

function Harden-Windows {
    #Not Completly tested, Use at your own risk
    #Disables Media Player libarary share
    Get-Service WMPNetworkSvc -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
    #Will help to prevent Demo mode from being enabled
    Get-Service RetailDemo -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
    #Disables Most remote access apps
    Get-Service RemoteAccess -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
    Get-Service RemoteRegistry -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
    Get-Service WinRM -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
    #User App Port Sharing
    Get-Service NetTcpPortSharing -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop

    #Disables Phone Home urls
    $ORgHost = Get-Content "$ENV:Windir\System32\drivers\etc\hosts"
    $ORgHost | Out-File "$ENV:Windir\System32\drivers\etc\hosts.bak" -Force -Encoding utf8
    $ORgHost | Out-File "$ENV:TEMP\TempHost.txt" -Force -Encoding utf8
    add-content -Value "0.0.0.0 telemetry.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 vortex.data.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 vortex-win.data.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 telecommand.telemetry.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 oca.telemetry.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 oca.telemetry.microsoft.com.nsatc.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 sqm.telemetry.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 watson.telemetry.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 watson.telemetry.microsoft.com.nsatc.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 redir.metaservices.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 choice.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 choice.microsoft.com.nsatc.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 df.telemetry.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 wes.df.telemetry.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 reports.wes.df.telemetry.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 services.wes.df.telemetry.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 sqm.df.telemetry.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 watson.ppe.telemetry.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 telemetry.appex.bing.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 telemetry.urs.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 telemetry.appex.bing.net:443" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 settings-sandbox.data.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 vortex-sandbox.data.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 watson.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 survey.watson.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 watson.live.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 statsfe2.ws.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 compatexchange.cloudapp.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 cs1.wpc.v0cdn.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 a-0001.a-msedge.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 fe2.update.microsoft.com.akadns.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 statsfe2.update.microsoft.com.akadns.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 sls.update.microsoft.com.akadns.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 diagnostics.support.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 corp.sts.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 statsfe1.ws.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 pre.footprintpredict.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 i1.services.social.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 i1.services.social.microsoft.com.nsatc.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 feedback.windows.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 feedback.microsoft-hohm.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 feedback.search.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 cdn.content.prod.cms.msn.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 cdn.content.prod.cms.msn.com.edgekey.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 e10663.g.akamaiedge.net" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 dmd.metaservices.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 schemas.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 go.microsoft.com" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 40.76.0.0/14" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 40.96.0.0/12" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 40.124.0.0/16" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 40.112.0.0/13" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 40.125.0.0/17" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 40.74.0.0/15" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 40.80.0.0/12" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 40.120.0.0/14" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 137.116.0.0/16" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 23.192.0.0/11" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 23.32.0.0/11" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 23.64.0.0/14" -path "$ENV:TEMP\TempHost.txt"
    add-content -Value "0.0.0.0 23.55.130.182" -path "$ENV:TEMP\TempHost.txt"
    Copy-Item -Path "$ENV:TEMP\TempHost.txt" -Destination "$ENV:Windir\System32\drivers\etc"
    Remove-Item "$ENV:Windir\System32\drivers\etc\hosts" -Force | Out-Null
    Rename-Item -Path "$ENV:Windir\System32\drivers\etc\TempHost.txt" -NewName "hosts"
    Remove-Item "$ENV:TEMP\TempHost.txt" -Force | Out-Null

}

#Checks to see what switches are being used
If (($StartMenuLayout) -and ($ExportStartMenuLayout)){Read-Error -ErrorText "You can not use ExportStartMenuLayout parameter and StartMenuLayout parameter at the sametime"}

#Exports the current start menu config
If ($ExportStartMenuLayout){Export-StartMenuLayout}

New-LogFile

#If a config file is specifed will import it
IF ($StartMenuLayout) {Import-StartMenuLayout}

#Enable RDP
IF ($EnableRDP) {Enable-RDP}

#Sets the Tiemzone
IF ($SetTimeZone) {Set-Time}

#Disabled UAC
IF ($DisableUAC){Disable-UAC}

#Disbales Xbox Services and stops them
If ($DisableXboxServices) {Disable-XboxServices}

#Add regkeys to disable OneDrive
If ($DisableOneDrive) {Disable-OneDrive}

#adds regkey needed to disable Cortana
If ($DisableCortana) {Disable-Cortana}

#Disables the windows store, The app is still listed
If ($DisableWindowsStore) {Disable-WindowsStore}

IF ($RemoveWindowsStoreApp) {Remove-WindowsStoreApp}

#Disables add on the start menu and lock screen
If ($DisableAds) {Disable-Ads}

#Disables Hibernate
If ($DisableHibernate) {Disable-Hibernate}

#Disables Windows Tips
If ($DisableWindowsTips) {Disable-WindowsTips}

#Disables Consumer Experience
If ($DisableConsumerExperience) {Disable-ConsumerExperience}

#Disable Connect to Windows Update Internet Location
IF ($DisableConnectToInternetUpdates) {Disable-ConnectToInternetUpdates}

#If a list file is specifyed will run the uninstall process
IF ($RemoveApps) {Remove-Apps}

if ($InstallDotNet35){Install-dotnet}

#renames the computer
If ($RenameComputer) {Rename-Computer -NewName $RenameComputer}

#Sets the page file
If ($SetPageFile) {Set-PageFile}

#Sets power config
IF ($SetPowerConfig) {Set-PowerConfig}

IF ($DisableSMBv1){Disable-SMBv1}

if ($Harden){Harden-Windows}

IF ($DisableLocationAndDataCollectionServices){Disable-LocationAndDataCollection}

#Reboots the computer
If ($Reboot){Restart-Computer -ComputerName $env:COMPUTERNAME ; Exit-Script}else{
    Write-Host "You will need to reboot the computer before you see the change take affect"
    Exit-Script
}