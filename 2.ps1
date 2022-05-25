#Remember to run as admin. (I pray you've learned that much by now) Set the variable below to the name of the primary admin account. (What you're logged into.)
Set-ExecutionPolicy -Scope CurrentUser unrestricted
$user = read-host "enter name"


#Disables powershell 2.0
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

#SMB stuff
function reg-key-edit($path,$name,$value_type,$value) {
   if($path) {
    set-itemproperty -path $path -name $name -value $value -Type $value_type -force
   }
   else {
      reg add $path /v $name /t $value_type /d $value /f
    }
}  

reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10\" "Start" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" "SMB1" "REG_DWORD" "0"
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

#SMB Packet Signing Enabled
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" "RequireSecuritySignature" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" "RequireSecuritySignature" "REG_DWORD" "1"

#RDP Stuff
#Disables
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" "fDisableCdm" "REG_DWORD" "1"
#Disables
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
#Enables
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

#Configures DEP
BCDEDIT /set "{current}" nx OptOut

#Rewrites Secpols/Sets up password reqs
cmd /c net accounts /lockoutduration:15

<#
$secpols = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 15
MaximumPasswordAge = 30
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
RequireLogonToChangePassword = 1
ForceLogoffWhenHourExpire = 1
NewAdministratorName = "AdminBOI"
NewGuestName = "GuestBOI"
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
EnableAdminAccount = 0
EnableGuestAccount = 0
[Event Audit]
AuditSystemEvents = 1
AuditLogonEvents = 1
AuditObjectAccess = 1
AuditPrivilegeUse = 1
AuditPolicyChange = 1
AuditAccountManage = 1
AuditProcessTracking = 1
AuditDSAccess = 1
AuditAccountLogon = 1
[Registry Values]
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"10"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,5
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption=1,"0"
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,5
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,3
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,""
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures=4,0
MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing=3,0
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,536870912
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,536870912
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,0
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=7,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog
MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown=4,0
MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,15
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=4,0
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1
[Privilege Rights]
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeSystemtimePrivilege = *S-1-5-19,*S-1-5-32-544
SeCreatePagefilePrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0
SeLoadDriverPrivilege = *S-1-5-32-544
SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559
SeServiceLogonRight = *S-1-5-80-0
SeInteractiveLogonRight = Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeSecurityPrivilege = *S-1-5-32-544
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = Guest
SeDenyInteractiveLogonRight = Guest
SeUndockPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeManageVolumePrivilege = *S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeIncreaseWorkingSetPrivilege = *S-1-5-32-545
SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-545
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDelegateSessionUserImpersonatePrivilege = *S-1-5-32-544
[Version]
signature="$CHICAGO$"
Revision=2
"@


New-Item C:\secpol.cfg
Set-Content -Path "C:\secpol.cfg" -Value "$secpols" -Force
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
rm -force c:\secpol.cfg -confirm:$false

#>

<#
#Registry key-based stuff
function reg-key-edit($path,$name,$value_type,$value,) {
   if($path) {
    set-itemproperty -path $path -name $name -value $value -Type $value_type -force
   }
   else {
      reg add $path /v $name /t $value_type /d $value /f
    }
}  
 #>
 
reg-key-edit "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveTimeOut" "REG_SZ" "600"
reg-key-edit "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveTimeOut" "REG_SZ" "600"
reg-key-edit "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" "ScreenSaverIsSecure" "REG_SZ" "1"
reg-key-edit "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" "ScreenSaverIsSecure" "REG_SZ" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\" "EnhancedAntiSpoofing" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" "DisableWindowsConsumerFeatures" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\" "EnableSmartScreen" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\" "ShellSmartScreenLevel" "REG_SZ" "Block"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer\" "NoDataExecutionPrevention" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" "AllowTelemetry" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" "RestrictRemoteSAM" "REG_SZ" "O:SYG:SYD:(A;;RC;;;BA)"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" "RestrictNullSessAccess" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" "RestrictAnonymous" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" "NoLMHash" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" "SupportedEncryptionTypes" "REG_DWORD" "2147483640"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" "AllowOnlineID" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\" "allownullsessionfallback" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP\" "LDAPClientIntegrity" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" "LmCompatibilityLevel" "REG_DWORD" "5"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\" "DODownloadMode" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" "MaxSize" "REG_DWORD" "32768"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer\" "NoHeapTerminationOnCorruption" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "MSAOptional" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" "RestrictRemoteClients" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" "DCSettingIndex" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\" "EnumerateLocalUsers" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" "fAllowToGetHelp" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" "ACSettingIndex" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "NoAutorun" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\" "DontDisplayNetworkSelectionUI" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" "MaxSize" "REG_DWORD" "1024000"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" "MaxSize" "REG_DWORD" "32768"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "PreXPSP2ShellProtocolBehavior" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "RequireStrongKey" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "MaximumPasswordAge" "REG_DWORD" "30"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\" "DisableExceptionChainValidation" "REG_DWORD" "0"

reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "SealSecureChannel" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "RequireSignOrSeal" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" "fPromptForPassword" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" "fEncryptRPCTraffic" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" "MinEncryptionLevel" "REG_DWORD" "3"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" "DisableEnclosureDownload" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" "AllowBasicAuthInClear" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" "AllowIndexingEncryptedStoresOrItems" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\" "EnableUserControl" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\" "AlwaysInstallElevated" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\" "SafeForScripting" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "DisableAutomaticRestartSignOn" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" "AllowUnencryptedTraffic" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization\" "NoLockScreenCamera" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" "EnableICMPRedirect" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" "DisableIPSourceRouting" "REG_DWORD" "2"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" "DisableIpSourceRouting" "REG_DWORD" "2"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization\" "NoLockScreenSlideshow" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" "NoNameReleaseOnDemand" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\" "FormSuggest Passwords" "REG_SZ" "no"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings\" "PreventCertErrorOverrides" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" "PreventOverrideAppRepUnknown" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" "PreventOverride" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\" "MinimumPINLength" "REG_DWORD" "6"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork\" "RequireSecurityDevice" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR\" "AllowGameDVR" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" "EnabledV9" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" "DisablePasswordSaving" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat\" "DisableInventory" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" "EnablePlainTextPassword" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer\" "NoAutoplayfornonVolume" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" "EnumerateAdministrators" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" "DisableThirdPartySuggestions" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" "AllowDomainPINLogon" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" "UseLogonCredential" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" "LimitBlankPasswordUse" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" "AllowProtectedCreds" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" "SCENoApplyLegacyAuditPolicy" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" "NTLMMinClientSec" "REG_DWORD" "537395200"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" "NTLMMinServerSec" "REG_DWORD" "537395200"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoReadingPane" "REG_DWORD" "1"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPreviewPane" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoReadingPane" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPreviewPane" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" "AllowUnencryptedTraffic" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" "AllowBasic" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" "AllowBasic" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "DisablePasswordChange" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "SignSecureChannel" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" "SaveZoneInformation" "REG_DWORD" "2"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" "NoToastApplicationNotificationOnLockScreen" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" "NoToastApplicationNotificationOnLockScreen" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableVirtualization" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" "DisableWebPnPDownload" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "NoWebServices" "REG_DWORD" "1"

reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" "DisableHTTPPrinting" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" "DriverLoadPolicy" "REG_DWORD" "3"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" "AllowDigest" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "ConsentPromptBehaviorUser" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "FilterAdministratorToken" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "ConsentPromptBehaviorAdmin" "REG_DWORD" "2"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" "EnableScriptBlockLogging" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableInstallerDetection" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\" "Enabled" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableSecureUIAPaths" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" "ProcessCreationIncludeCmdLine_Enabled" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\" "AutoConnectAllowedOEM" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\" "fMinimizeConnections" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\" "EccCurves" "REG_MULTI_SZ" "NistP384 NistP256"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections\" "NC_ShowSharedAccessUI" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" "AllowInsecureGuestAuth" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\batfile\shell\runasuser\" "SuppressionPolicy" "REG_DWORD" "4096"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\cmdfile\shell\runasuser\" "SuppressionPolicy" "REG_DWORD" "4096"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runasuser\" "SuppressionPolicy" "REG_DWORD" "4096"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\mscfile\shell\runasuser\" "SuppressionPolicy" "REG_DWORD" "4096"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "InactivityTimeoutSecs" "REG_DWORD" "600"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "LegalNoticeText" "REG_SZ" "This is a logon banner. Ben, if you are seeing this, Adam is better. Let's win this bois. ggez."
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "LegalNoticeCaption" "REG_SZ" "EHS Cyber Knights"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" "CachedLogonsCount" "REG_SZ" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\" "LetAppsActivateWithVoiceAboveLock" "REG_DWORD" "2"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\" "LetAppsActivateWithVoice" "REG_DWORD" "2"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" "RestrictAnonymousSAM" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\" "ProtectionMode" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" "DisableRunAs" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableLUA" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\" "EnableTranscripting" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\" "NoDriveTypeAutoRun" "REG_DWORD" "255"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AutoInstallMinorUpdates" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" "AUOptions" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DisableWindowsUpdateAccess" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ElevateNonAdmins" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\Internet Communication Management\Internet Communication" "DisableWindowsUpdateAccess" "REG_DWORD" "0"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWindowsUpdate" "REG_DWORD" "0"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" "DisableWindowsUpdateAccess" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateCDRoms" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateFloppies" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" "AuditLevel" "REG_DWORD" "8"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "auditbaseobjects" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "fullprivilegeauditing" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "restrictanonymous" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "disabledomaincreds" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "everyoneincludesanonymous" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "UseMachineId" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "dontdisplaylastusername" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "undockwithoutlogon" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" "autodisconnect" "REG_DWORD" "45"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" "enablesecuritysignature" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" "requiresecuritysignature" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" "NullSessionPipes" "REG_MULTI_SZ" "netlogon, samr, lsarpc"
##reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" "NullSessionShares" "REG_MULTI_SZ" """"
##reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" "Machine" "REG_MULTI_SZ" """"
##reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" "Machine" "REG_MULTI_SZ" """"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" "EnabledV8" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "DisablePasswordCaching" "REG_DWORD" "1"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "DisablePasswordCaching" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "WarnonBadCertRecving" "REG_DWORD" "1"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "WarnonBadCertRecving" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "WarnOnPostRedirect" "REG_DWORD" "1"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "WarnOnPostRedirect" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" "REG_DWORD" "1"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\.DEFAULT\Control Panel\Accessibility\StickyKeys" "Flags" "REG_SZ" "506"
reg-key-edit "HKEY_CURRENT_USER\.DEFAULT\Control Panel\Accessibility\StickyKeys" "Flags" "REG_SZ" "506"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSuperHidden" "REG_DWORD" "1"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSuperHidden" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" "CrashDumpEnabled" "REG_DWORD" "0"
reg-key-edit "HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Control\CrashControl" "CrashDumpEnabled" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDROM" "AutoRun" "REG_DWORD" "1"
reg-key-edit "HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Services\CDROM" "AutoRun" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" "REG_DWORD" "255"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\access\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\access\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" "excelbypassencryptedmacroscan" "REG_DWORD" "0"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" "excelbypassencryptedmacroscan" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" "level" "REG_DWORD" "4"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" "level" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" "level" "REG_DWORD" "4"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" "level" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\word\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\word\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\word\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\word\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\word\security" "wordbypassencryptedmacroscan" "REG_DWORD" "0"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\word\security" "wordbypassencryptedmacroscan" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\common\security" "automationsecurity" "REG_DWORD" "3"
reg-key-edit "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\common\security" "automationsecurity" "REG_DWORD" "3"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" "ServiceKeepAlive" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "CheckForSignaturesBeforeRunningScan" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableHeuristics" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" "ScanWithAntiVirus" "REG_DWORD" "3"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" "VLimitEnhancedDiagnosticDataWindowsAnalytics" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\" "fBlockNonDomain" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient" "QueryNetBTFQDN" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient" "NameServer" "REG_SZ" "8.8.8.8 8.8.4.4"
reg-key-edit "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient" "RegistrationTtl" "REG_DWORD" "600"
reg-key-edit "HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Peernet" "IgnoreDomainPasswordPolicyForNewGroups" "REG_DWORD" "0"
#Printer-
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint" "Enabled" "REG_DWORD" "0"
#RDP- only comment out if you lose points
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" "Enabled" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" "Enabled" "REG_DWORD" "0"
#UPnP-disable unsolicited
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" "Enabled" "REG_DWORD" "0"

reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\GloballyOpenPorts" "AllowUserPrefMerge" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" "LogDroppedPackets" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" "LogSuccessfulConnections" "REG_DWORD" "1"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" "LogFilePath" "REG_SZ" "	%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" "LogFileSize" "REG_DWORD" "4096"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\GloballyOpenPorts" "Enabled" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" "DisableNotifications" "REG_DWORD" "0"
reg-key-edit "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" "EnableFirewall" "REG_DWORD" "1"


#disables default guest and admin/renames them
  Write-Warning "disabling Guest and Admin account"
    Get-LocalUser Guest | Disable-LocalUser
    Get-LocalUser Administrator | Disable-LocalUser
    Write-Warning "renaming guest and admin account adminBOI && guestBOI"
    $adminAccount =Get-WMIObject Win32_UserAccount -Filter "Name='Administrator'"
    $result =$adminAccount.Rename("adminBOI")
    $guestAccount =Get-WMIObject Win32_UserAccount -Filter "Name='Guest'"
    $result =$guestAccount.Rename("guestBOI")

#Changes all user passwords to 195077045605Apb!
Write-Warning "rewriting passwords; changing to 195077045605Apb!"
    Get-WmiObject win32_useraccount | Foreach-object {
    ([adsi]("WinNT://"+$_.caption).replace("\","/")).SetPassword("195077045605Apb!")
    }
    
	
#Flush DNS

ipconfig /flushdns

#Enables autoupdates, check this.. been added to reg stuff above

#Update Defender signatures, other misc configs
setx /M MP_FORCE_USE_SANDBOX 1
cmd.exe /c "%ProgramFiles%"\"Windows Defender"\MpCmdRun.exe -SignatureUpdate
Set-MpPreference -PUAProtection enable

#Setting ASRs
#WMI persistance
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
#smb lateral movement
Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D -AttackSurfaceReductionRules_Actions Enabled
#ransomeware protection
Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
#prevent stealing from LSASS
Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled

#Disabling IIS Stuff...  if IIS isn't needed
dism /online /disable-feature /featurename:IIS-WebServerRole
dism /online /disable-feature /featurename:IIS-WebServer
dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
dism /online /disable-feature /featurename:IIS-HttpErrors
dism /online /disable-feature /featurename:IIS-HttpRedirect
dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
dism /online /disable-feature /featurename:IIS-NetFxExtensibility
dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
dism /online /disable-feature /featurename:IIS-HttpLogging
dism /online /disable-feature /featurename:IIS-LoggingLibraries
dism /online /disable-feature /featurename:IIS-RequestMonitor
dism /online /disable-feature /featurename:IIS-HttpTracing
dism /online /disable-feature /featurename:IIS-Security
dism /online /disable-feature /featurename:IIS-URLAuthorization
dism /online /disable-feature /featurename:IIS-RequestFiltering
dism /online /disable-feature /featurename:IIS-IPSecurity
dism /online /disable-feature /featurename:IIS-Performance
dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
dism /online /disable-feature /featurename:IIS-WebServerManagementTools
dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
dism /online /disable-feature /featurename:IIS-Metabase
dism /online /disable-feature /featurename:IIS-HostableWebCore
dism /online /disable-feature /featurename:IIS-StaticContent
dism /online /disable-feature /featurename:IIS-DefaultDocument
dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
dism /online /disable-feature /featurename:IIS-WebDAV
dism /online /disable-feature /featurename:IIS-WebSockets
dism /online /disable-feature /featurename:IIS-ApplicationInit
dism /online /disable-feature /featurename:IIS-ASPNET
dism /online /disable-feature /featurename:IIS-ASPNET45
dism /online /disable-feature /featurename:IIS-ASP
dism /online /disable-feature /featurename:IIS-CGI 
dism /online /disable-feature /featurename:IIS-ISAPIExtensions
dism /online /disable-feature /featurename:IIS-ISAPIFilter
dism /online /disable-feature /featurename:IIS-ServerSideIncludes
dism /online /disable-feature /featurename:IIS-CustomLogging
dism /online /disable-feature /featurename:IIS-BasicAuthentication
dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
dism /online /disable-feature /featurename:IIS-ManagementConsole
dism /online /disable-feature /featurename:IIS-ManagementService
dism /online /disable-feature /featurename:IIS-WMICompatibility
dism /online /disable-feature /featurename:IIS-LegacyScripts
dism /online /disable-feature /featurename:IIS-LegacySnapIn
dism /online /disable-feature /featurename:IIS-FTPServer
dism /online /disable-feature /featurename:IIS-FTPSvc
dism /online /disable-feature /featurename:IIS-FTPExtensibility
	
	
#disables TFTP, check if req'd
dism /online /disable-feature /featurename:TFTP

#Disables Telnet, check if req'd
dism /online /disable-feature /featurename:TelnetClient
dism /online /disable-feature /featurename:TelnetServer
	

#Rewrites etc\hosts
$hosts = @" 
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
"@

Set-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$hosts" -Force


#Grabs potential suspicious files and copies them into "may be bad shit" directory on your desktop. Will be alot, but definitely worth going through. Remember, these are **JUST COPIES** find the originals. Remember, the folder names only indicate location, not file type.



    New-Item -Path C:\Users\$user\Desktop\SuspiciousCopies -ItemType directory
    'no files are safe [.][.]'
    New-Item -Path C:\Users\$user\Desktop\SuspiciousCopies\userfiles -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\SuspiciousCopies\programfiles -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\SuspiciousCopies\programfilesx86 -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\SuspiciousCopies\documents -ItemType directory
	New-Item -Path C:\Users\$user\Desktop\SuspiciousCopies\OS_search_engine -ItemType directory
    Write-Warning "grabbing user files"
    Get-ChildItem -Path "C:\Users\*" -Include *.aac,*.ac3,*.avi,*.aiff,*.bat,*.exe,*.flac,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.ogg,*.txt,*.sh,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\SuspiciousCopies\userfiles
    Write-Warning "grabbing program files"
    Get-ChildItem -Path "C:\Program Files\*" -Include *.aac,*.ac3,*.avi,*.aiff,*.bat,*.exe,*.flac,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.ogg,*.txt,*.sh,*.wma,*.vqf,*.pcap,*.zip,*.pdf -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\SuspiciousCopies\programfiles
    Get-ChildItem -Path "C:\Program Files (x86)\*" -Include *.aac,*.ac3,*.avi,*.aiff,*.bat,*.exe,*.flac,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.ogg,*.txt,*.sh,*.wma,*.vqf,*.pcap,*.zip,*.pdf -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\SuspiciousCopies\programfilesx86
    Write-Warning "grabbing Documents"
    Get-ChildItem -Path "C:\Users\$user\Documents\*" -Include *.aac,*.ac3,*.avi,*.aiff,*.bat,*.exe,*.flac,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.ogg,*.txt,*.sh,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\SuspiciousCopies\documentsandsettings
    Write-Warning "media files up next!"
    Get-ChildItem -Path C:\Users -Include *.jpg,*.png,*.jpeg,*.avi,*.mp4,*.mp3,*.wav -Exclude *.dll,.doc,*.docx,  -File -Recurse -ErrorAction SilentlyContinue | Out-File -filepath C:\Users\$user\Desktop\SuspiciousCopies\Mediafiles.txt

	
#Lists network shares in a log-like file in the "suspicious" directory. Adam anticipates there being a vuln here this time around, so be sure to check it.
Write-Warning "grabbing smb shares"
    net share > SuspiciousCopies\shares.txt
 
 #Enables bitlocker with a boot pin of 299633
$SecureString = ConvertTo-SecureString "299633" -AsPlainText -Force
sleep -Seconds 2
Enable-BitLocker -MountPoint c: -EncryptionMethod Aes256 -UsedSpaceOnly -Pin $SecureString -TPMandPinProtector

#Blocks commonly exploited binaries from making network connections, enables firewall

netsh advfirewall set allprofiles state on
netsh advfirewall reset

netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
	
#Screw Audits, I'm doing this
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable
	

#Service management
#Bad Services
cmd.exe /c 'sc stop tlntsvr'
cmd.exe /c 'sc config tlntsvr start= disabled'
cmd.exe /c 'sc stop Telephony'
cmd.exe /c 'sc config Telephony start= disabled'
cmd.exe /c 'sc stop ShellHWDetection'
cmd.exe /c 'sc config ShellHWDetection start= disabled'
cmd.exe /c 'sc stop WinHttpAutoProxySvc'
cmd.exe /c 'sc config WinHttpAutoProxySvc start= disabled'
cmd.exe /c 'sc stop SZCSVC'
cmd.exe /c 'sc config SZCSVC start= disabled'
cmd.exe /c 'sc stop msftpsvc'
cmd.exe /c 'sc config msftpsvc start= disabled'
cmd.exe /c 'sc stop snmptrap'
cmd.exe /c 'sc config snmptrap start= disabled'
cmd.exe /c 'sc stop ssdpsrv'
cmd.exe /c 'sc config ssdpsrv start= disabled'
cmd.exe /c 'sc stop termservice'
cmd.exe /c 'sc config termservice start= disabled'
cmd.exe /c 'sc stop sessionenv'
cmd.exe /c 'sc config sessionenv start= disabled'
cmd.exe /c 'sc stop remoteregistry'
cmd.exe /c 'sc config remoteregistry start= disabled'
cmd.exe /c 'sc stop Messenger'
cmd.exe /c 'sc config Messenger start= disabled'
cmd.exe /c 'sc stop upnphos'
cmd.exe /c 'sc config upnphos start= disabled'
cmd.exe /c 'sc stop WAS'
cmd.exe /c 'sc config WAS start= disabled'
#Remote Access//RDP
#cmd.exe /c 'sc stop RemoteAccess'
#cmd.exe /c 'sc config RemoteAccess start= disabled'
cmd.exe /c 'sc stop mnmsrvc'
cmd.exe /c 'sc config mnmsrvc start= disabled'
cmd.exe /c 'sc stop NetTcpPortSharing'
cmd.exe /c 'sc config NetTcpPortSharing start= disabled'
cmd.exe /c 'sc stop RasMan'
cmd.exe /c 'sc config RasMan start= disabled'
cmd.exe /c 'sc stop TabletInputService'
cmd.exe /c 'sc config TabletInputService start= disabled'
cmd.exe /c 'sc stop RpcSs'
cmd.exe /c 'sc config RpcSs start= disabled'
cmd.exe /c 'sc stop SENS'
cmd.exe /c 'sc config SENS start= disabled'
cmd.exe /c 'sc stop EventSystem'
cmd.exe /c 'sc config EventSystem start= disabled'
cmd.exe /c 'sc stop XblAuthManager'
cmd.exe /c 'sc config XblAuthManager start= disabled'
cmd.exe /c 'sc stop XblGameSave'
cmd.exe /c 'sc config XblGameSave start= disabled'
cmd.exe /c 'sc stop XboxGipSvc'
cmd.exe /c 'sc config XboxGipSvc start= disabled'
cmd.exe /c 'sc stop xboxgip'
cmd.exe /c 'sc config xboxgip start= disabled'
cmd.exe /c 'sc stop xbgm'
cmd.exe /c 'sc config xbgm start= disabled'
cmd.exe /c 'sc stop SysMain'
cmd.exe /c 'sc config SysMain start= disabled'
cmd.exe /c 'sc stop seclogon'
cmd.exe /c 'sc config seclogon start= disabled'
cmd.exe /c 'sc stop TapiSrv'
cmd.exe /c 'sc config TapiSrv start= disabled'
cmd.exe /c 'sc stop p2pimsvc'
cmd.exe /c 'sc config p2pimsvc start= disabled'
cmd.exe /c 'sc stop simptcp'
cmd.exe /c 'sc config simptcp start= disabled'
cmd.exe /c 'sc stop fax'
cmd.exe /c 'sc config fax start= disabled'
cmd.exe /c 'sc stop Msftpsvc'
cmd.exe /c 'sc config Msftpsvc start= disabled'
cmd.exe /c 'sc stop iprip'
cmd.exe /c 'sc config iprip start= disabled'
cmd.exe /c 'sc stop ftpsvc'
cmd.exe /c 'sc config ftpsvc start= disabled'
    cmd.exe /c 'sc stop RasAuto'
    cmd.exe /c 'sc config RasAuto start= disabled'
    cmd.exe /c 'sc stop W3svc'
    cmd.exe /c 'sc config W3svc start= disabled'
    cmd.exe /c 'sc stop Smtpsvc'
    cmd.exe /c 'sc config Smtpsvc start= disabled'
    cmd.exe /c 'sc stop Dfs'
    cmd.exe /c 'sc config Dfs start= disabled'
    cmd.exe /c 'sc stop TrkWks'
    cmd.exe /c 'sc config TrkWks start= disabled'
    cmd.exe /c 'sc stop MSDTC'
    cmd.exe /c 'sc config MSDTC start= disabled'
    cmd.exe /c 'sc stop ERSvc'
    cmd.exe /c 'sc config ERSvc start= disabled'
    cmd.exe /c 'sc stop NtFrs'
  cmd.exe /c 'sc config NtFrs start= disabled'
#IIS Stuff
#cmd.exe /c 'sc stop Iisadmin'
#cmd.exe /c 'sc config Iisadmin start= disabled'
    cmd.exe /c 'sc stop IsmServ'
    cmd.exe /c 'sc config IsmServ start= disabled'
    cmd.exe /c 'sc stop WmdmPmSN'
    cmd.exe /c 'sc config WmdmPmSN start= disabled'
    cmd.exe /c 'sc stop helpsvc'
    cmd.exe /c 'sc config helpsvc start= disabled'
    cmd.exe /c 'sc stop Spooler'
    cmd.exe /c 'sc config Spooler start= disabled'
    cmd.exe /c 'sc stop RDSessMgr'
    cmd.exe /c 'sc config RDSessMgr start= disabled'
    cmd.exe /c 'sc stop RSoPProv'
    cmd.exe /c 'sc config RSoPProv start= disabled'
    cmd.exe /c 'sc stop SCardSvr'
    cmd.exe /c 'sc config SCardSvr start= disabled'
    cmd.exe /c 'sc stop lanmanserver'
    cmd.exe /c 'sc config lanmanserver start= disabled'
    cmd.exe /c 'sc stop Sacsvr'
    cmd.exe /c 'sc config Sacsvr start= disabled'
    cmd.exe /c 'sc stop TermService'
    cmd.exe /c 'sc config TermService start= disabled'
    cmd.exe /c 'sc stop uploadmgr'
    cmd.exe /c 'sc config uploadmgr start= disabled'
    cmd.exe /c 'sc stop VDS'
    cmd.exe /c 'sc config VDS start= disabled'
    cmd.exe /c 'sc stop VSS'
    cmd.exe /c 'sc config VSS start= disabled'
    cmd.exe /c 'sc stop WINS'
    cmd.exe /c 'sc config WINS start= disabled'
    cmd.exe /c 'sc stop CscService'
    cmd.exe /c 'sc config CscService start= disabled'
    cmd.exe /c 'sc stop hidserv'
    cmd.exe /c 'sc config hidserv start= disabled'
    cmd.exe /c 'sc stop IPBusEnum'
    cmd.exe /c 'sc config IPBusEnum start= disabled'
    cmd.exe /c 'sc stop PolicyAgent'
    cmd.exe /c 'sc config PolicyAgent start= disabled'
    cmd.exe /c 'sc stop SCPolicySvc'
    cmd.exe /c 'sc config SCPolicySvc start= disabled'
    cmd.exe /c 'sc stop SharedAccess'
    cmd.exe /c 'sc config SharedAccess start= disabled'
    cmd.exe /c 'sc stop SSDPSRV'
    cmd.exe /c 'sc config SSDPSRV start= disabled'
    cmd.exe /c 'sc stop Themes'
    cmd.exe /c 'sc config Themes start= disabled'
    cmd.exe /c 'sc stop upnphost'
    cmd.exe /c 'sc config upnphost start= disabled'
    cmd.exe /c 'sc stop nfssvc'
    cmd.exe /c 'sc config nfssvc start= disabled'
    cmd.exe /c 'sc stop nfsclnt'
    cmd.exe /c 'sc config nfsclnt start= disabled'
#MSSQL
cmd.exe /c 'sc stop MSSQLServerADHelper'
cmd.exe /c 'sc config MSSQLServerADHelper start= disabled'

    cmd.exe /c 'sc stop SharedAccess'
    cmd.exe /c 'sc config SharedAccess start= disabled'
    cmd.exe /c 'sc stop UmRdpService'
    cmd.exe /c 'sc config UmRdpService start= disabled'
    cmd.exe /c 'sc stop SessionEnv'
    cmd.exe /c 'sc config SessionEnv start= disabled'
    cmd.exe /c 'sc stop TeamViewer'
    cmd.exe /c 'sc config TeamViewer start= disabled'
    cmd.exe /c 'sc stop TeamViewer7'
    cmd.exe /c 'sc config start= disabled'
    cmd.exe /c 'sc stop HomeGroupListener'
    cmd.exe /c 'sc config HomeGroupListener start= disabled'
    cmd.exe /c 'sc stop HomeGroupProvider'
    cmd.exe /c 'sc config HomeGroupProvider start= disabled'
    cmd.exe /c 'sc stop AxInstSV'
    cmd.exe /c 'sc config AXInstSV start= disabled'
    cmd.exe /c 'sc stop Netlogon'
    cmd.exe /c 'sc config Netlogon start= disabled'
    cmd.exe /c 'sc stop lltdsvc'
    cmd.exe /c 'sc config lltdsvc start= disabled'
    cmd.exe /c 'sc stop iphlpsvc'
    cmd.exe /c 'sc config iphlpsvc start= disabled'
    cmd.exe /c 'sc stop AdobeARMservice'
    cmd.exe /c 'sc config AdobeARMservice start= disabled'
 
 
#Good Services
    cmd.exe /c 'sc start wuauserv'
    cmd.exe /c 'sc config wuauserv start= auto'
    cmd.exe /c 'sc start EventLog'
    cmd.exe /c 'sc config EventLog start= auto'
    cmd.exe /c 'sc start MpsSvc'
    cmd.exe /c 'sc config MpsSvc start= auto'
    cmd.exe /c 'sc start WinDefend'
    cmd.exe /c 'sc config WinDefend start= auto'
    cmd.exe /c 'sc start WdNisSvc'
    cmd.exe /c 'sc config WdNisSvc start= auto'
    cmd.exe /c 'sc start Sense'
    cmd.exe /c 'sc config Sense start= auto'
    cmd.exe /c 'sc start Schedule'
    cmd.exe /c 'sc config Schedule start= auto'
    cmd.exe /c 'sc start SCardSvr'
    cmd.exe /c 'sc config SCardSvr start= auto'
    cmd.exe /c 'sc start ScDeviceEnum'
    cmd.exe /c 'sc config ScDeviceEnum start= auto'
    cmd.exe /c 'sc start SCPolicySvc'
    cmd.exe /c 'sc config SCPolicySvc start= auto'
    cmd.exe /c 'sc start wscsvc'
    cmd.exe /c 'sc config wscsvc start= auto'


#Setting passwords to expire
wmic UserAccount set PasswordExpires=True
wmic UserAccount set PasswordChangeable=True
wmic UserAccount set PasswordRequired=True



#Check DEP exceptions
#remove all .pfx and .p12 files


#store using reversible encryption disabled
#disable send unencrypted password to third party smb servers
#check uac- 2.3.17.3
#5, system services
#Use CIS 9.3 for firewall
#17.5,17.7 audit account
#18.5.10.2
#18.5.11.1
#18.8.14
#18.8.22.1.1
#18.8.34.6
#18.9.13
#18.9.15
#18.9.35
#18.9.45.4.3.1
#18.9.45.8
#18.9.62.2.2
#18.9.62.3.10.1
#18.9.85
#18.9.97.2.2
#18.9.98.1
#19.7.8
#19.7.43.1
#Add winscript2 to checklist
#User management is req'd in checklist
#Add netstat function from winscript1
#Run sfc /scannow in cmd
#Update machine
#Check deployed printers
#only let admins execute
